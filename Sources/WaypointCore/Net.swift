import Foundation
import Darwin

/// Сетевые утилиты движка.
enum Net {

    struct NetError: LocalizedError {
        let message: String
        var errorDescription: String? { L10n.string(message) }
    }

    /// Свободный TCP-порт: слушаем на нулевом порту, узнаём выданный ядром и
    /// сразу освобождаем. Гонка теоретически возможна, но окно — миллисекунды.
    static func freePort() -> Int? {
        freePorts(count: 1)?.first
    }

    /// Выделяет несколько гарантированно разных loopback-портов. Сокеты
    /// удерживаются одновременно до получения всего набора, затем закрываются
    /// непосредственно перед запуском xray.
    static func freePorts(count: Int) -> [Int]? {
        guard count >= 0 else { return nil }
        guard count > 0 else { return [] }

        var sockets: [Int32] = []
        var ports: [Int] = []
        defer { sockets.forEach { close($0) } }

        for _ in 0..<count {
            let fd = socket(AF_INET, SOCK_STREAM, 0)
            guard fd >= 0 else { return nil }
            sockets.append(fd)

            var addr = sockaddr_in()
            addr.sin_family = sa_family_t(AF_INET)
            addr.sin_port = 0
            addr.sin_addr.s_addr = inet_addr("127.0.0.1")
            addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)

            let bound = withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            guard bound == 0 else { return nil }

            var actual = sockaddr_in()
            var len = socklen_t(MemoryLayout<sockaddr_in>.size)
            let got = withUnsafeMutablePointer(to: &actual) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    getsockname(fd, $0, &len)
                }
            }
            guard got == 0 else { return nil }
            ports.append(Int(UInt16(bigEndian: actual.sin_port)))
        }
        return ports
    }

    /// Ждёт, пока порт начнёт принимать соединения.
    static func waitPortOpen(host: String, port: Int, timeout: TimeInterval) async -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if canConnect(host: host, port: port) { return true }
            try? await Task.sleep(nanoseconds: 120_000_000)
        }
        return false
    }

    private static func canConnect(host: String, port: Int) -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = UInt16(port).bigEndian
        addr.sin_addr.s_addr = inet_addr(host)
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)

        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        return result == 0
    }

    /// GET через HTTP-прокси методом абсолютного URI, поверх сырого сокета.
    ///
    /// URLSession здесь не подходит: connectionProxyDictionary на macOS
    /// применяется не ко всем запросам и молча пропускает их напрямую, мимо
    /// прокси — тест туннеля тогда показывает домашний IP вместо выходного.
    /// Сокет исключает эту неоднозначность: запрос точно уходит в xray.
    static func fetchThroughHTTPProxy(
        proxyHost: String, proxyPort: Int, url: String, timeout: TimeInterval
    ) async throws -> String {
        guard let target = URL(string: url), let host = target.host else {
            throw NetError(message: "Некорректный URL")
        }

        return try await withCheckedThrowingContinuation { continuation in
            // Сетевые вызовы блокирующие — уводим их с исполнителя конкурентности.
            Thread.detachNewThread {
                do {
                    let body = try syncFetchViaProxy(
                        proxyHost: proxyHost, proxyPort: proxyPort,
                        absoluteURL: url, hostHeader: host, timeout: timeout
                    )
                    continuation.resume(returning: body)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }

    private static func syncFetchViaProxy(
        proxyHost: String, proxyPort: Int, absoluteURL: String,
        hostHeader: String, timeout: TimeInterval
    ) throws -> String {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw NetError(message: "Не удалось создать сокет") }
        defer { close(fd) }

        var tv = timeval(
            tv_sec: Int(timeout),
            tv_usec: Int32((timeout - Double(Int(timeout))) * 1_000_000)
        )
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = UInt16(proxyPort).bigEndian
        addr.sin_addr.s_addr = inet_addr(proxyHost)
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)

        let connected = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard connected == 0 else {
            throw NetError(message: "Прокси не принял соединение")
        }

        let request = """
        GET \(absoluteURL) HTTP/1.1\r
        Host: \(hostHeader)\r
        User-Agent: waypoint\r
        Connection: close\r
        \r

        """
        let out = Array(request.utf8)
        var sent = 0
        while sent < out.count {
            let n = out.withUnsafeBytes { buf -> Int in
                send(fd, buf.baseAddress!.advanced(by: sent), out.count - sent, 0)
            }
            guard n > 0 else { throw NetError(message: "Не удалось отправить запрос") }
            sent += n
        }

        var response = Data()
        var chunk = [UInt8](repeating: 0, count: 8192)
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            let n = recv(fd, &chunk, chunk.count, 0)
            if n > 0 {
                response.append(contentsOf: chunk[0..<n])
                // Ответ /cdn-cgi/trace короткий; ограничиваем на случай,
                // если сервер не закроет соединение.
                if response.count > 64 * 1024 { break }
            } else if n == 0 {
                break  // сервер закрыл соединение
            } else {
                if errno == EINTR { continue }
                break  // таймаут или ошибка
            }
        }

        guard !response.isEmpty, let text = String(data: response, encoding: .utf8) else {
            throw NetError(message: "Таймаут запроса через прокси")
        }
        // Отделяем тело от заголовков.
        guard let sep = text.range(of: "\r\n\r\n") else {
            throw NetError(message: "Некорректный ответ прокси")
        }
        let statusLine = text[..<(text.firstIndex(of: "\r") ?? text.startIndex)]
        if let code = statusLine.split(separator: " ").dropFirst().first.flatMap({ Int($0) }),
           !(200..<400).contains(code) {
            throw NetError(message: L10n.format("HTTP %lld через прокси", code))
        }
        return String(text[sep.upperBound...])
    }

    /// Обычный GET — для загрузки подписки.
    static func get(url: String, timeout: TimeInterval) async throws -> String {
        guard let u = URL(string: url) else {
            throw NetError(message: "Некорректный URL подписки")
        }
        var request = URLRequest(url: u)
        request.setValue("waypoint/1.0", forHTTPHeaderField: "User-Agent")
        request.timeoutInterval = timeout

        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = timeout
        let session = URLSession(configuration: config)
        defer { session.finishTasksAndInvalidate() }

        let (data, response) = try await session.data(for: request)
        if let http = response as? HTTPURLResponse, http.statusCode != 200 {
            throw NetError(
                message: L10n.format(
                    "HTTP %lld при загрузке подписки",
                    http.statusCode
                )
            )
        }
        guard let text = String(data: data, encoding: .utf8) else {
            throw NetError(message: "Подписка не в текстовом формате")
        }
        return text
    }
}
