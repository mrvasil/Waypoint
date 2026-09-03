import Foundation

/// Динамическое JSON-значение.
///
/// Конфиг xray структурно разный для каждого протокола и транспорта: у vless
/// свой `vnext`, у shadowsocks — `servers`, у wireguard — `peers`, а
/// `streamSettings` меняется от `wsSettings` до `realitySettings`. Описывать это
/// статическими типами — десятки структур, почти все опциональные; вместо этого
/// собираем дерево значений и сериализуем его напрямую.
public enum JSONValue: Equatable, Sendable {
    case string(String)
    case int(Int)
    case double(Double)
    case bool(Bool)
    case array([JSONValue])
    case object([String: JSONValue])
    case null
}

// MARK: - Литералы

extension JSONValue: ExpressibleByStringLiteral {
    public init(stringLiteral value: String) { self = .string(value) }
}

extension JSONValue: ExpressibleByIntegerLiteral {
    public init(integerLiteral value: Int) { self = .int(value) }
}

extension JSONValue: ExpressibleByBooleanLiteral {
    public init(booleanLiteral value: Bool) { self = .bool(value) }
}

extension JSONValue: ExpressibleByArrayLiteral {
    public init(arrayLiteral elements: JSONValue...) { self = .array(elements) }
}

extension JSONValue: ExpressibleByDictionaryLiteral {
    public init(dictionaryLiteral elements: (String, JSONValue)...) {
        self = .object(Dictionary(uniqueKeysWithValues: elements))
    }
}

// MARK: - Доступ

extension JSONValue {
    public var stringValue: String? { if case .string(let s) = self { return s }; return nil }
    public var intValue: Int? {
        switch self {
        case .int(let i): return i
        case .double(let d): return Int(d)
        case .string(let s): return Int(s)
        default: return nil
        }
    }
    public var boolValue: Bool? { if case .bool(let b) = self { return b }; return nil }
    public var arrayValue: [JSONValue]? { if case .array(let a) = self { return a }; return nil }
    public var objectValue: [String: JSONValue]? { if case .object(let o) = self { return o }; return nil }

    public subscript(key: String) -> JSONValue? {
        get { objectValue?[key] }
        set {
            guard case .object(var o) = self else { return }
            o[key] = newValue
            self = .object(o)
        }
    }

    public subscript(index: Int) -> JSONValue? {
        guard let a = arrayValue, a.indices.contains(index) else { return nil }
        return a[index]
    }
}

// MARK: - Сборка объектов

extension JSONValue {
    /// Собирает объект, отбрасывая nil-значения и пустые массивы.
    ///
    /// Это перенос `pruneUndef` из JS-версии: xray отвергает конфиг, где
    /// присутствует ключ с пустым значением там, где ожидается осмысленное,
    /// поэтому такие ключи не должны попадать в вывод вообще.
    public static func pruned(_ pairs: [String: JSONValue?]) -> JSONValue {
        var out: [String: JSONValue] = [:]
        for (key, value) in pairs {
            guard let value else { continue }
            if case .null = value { continue }
            if case .array(let a) = value, a.isEmpty { continue }
            if case .string(let s) = value, s.isEmpty { continue }
            out[key] = value
        }
        return .object(out)
    }

    /// Слияние с приоритетом у `other` — для наложения sockopt на streamSettings.
    public func merging(_ other: JSONValue) -> JSONValue {
        guard case .object(var mine) = self, case .object(let theirs) = other else { return other }
        for (k, v) in theirs { mine[k] = v }
        return .object(mine)
    }
}

// MARK: - Codable

extension JSONValue: Codable {
    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null; return }
        // Bool проверяется до чисел: JSONDecoder иначе разберёт true как 1.
        if let b = try? c.decode(Bool.self) { self = .bool(b); return }
        if let i = try? c.decode(Int.self) { self = .int(i); return }
        if let d = try? c.decode(Double.self) { self = .double(d); return }
        if let s = try? c.decode(String.self) { self = .string(s); return }
        if let a = try? c.decode([JSONValue].self) { self = .array(a); return }
        if let o = try? c.decode([String: JSONValue].self) { self = .object(o); return }
        throw DecodingError.dataCorruptedError(in: c, debugDescription: "Неизвестное JSON-значение")
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .string(let s): try c.encode(s)
        case .int(let i): try c.encode(i)
        case .double(let d): try c.encode(d)
        case .bool(let b): try c.encode(b)
        case .array(let a): try c.encode(a)
        case .object(let o): try c.encode(o)
        case .null: try c.encodeNil()
        }
    }
}
