import Foundation

/// Exact `±[Class selector]` or `±[Class(Category) selector]` syntax. The first ASCII
/// space separates owner and selector; neither is trimmed or case-folded. A selector
/// contains no Character.isWhitespace, and an owner has either no parentheses or
/// one nonempty category in one pair ending the owner. No Objective-C identifier
/// restrictions beyond that grammar are inferred.
struct ObjCMethodNameParts: Equatable, Sendable {
    let isClassMethod: Bool
    let className: String
    let category: String?
    let selector: String

    init?(_ name: String) {
        let scalars = name.unicodeScalars
        guard scalars.count >= 5, let sign = scalars.first, sign == "-" || sign == "+",
              scalars.dropFirst().first == "[", scalars.last == "]" else { return nil }
        let content = scalars.dropFirst(2).dropLast()
        guard let space = content.firstIndex(of: " "), space != content.startIndex else { return nil }
        let owner = content[..<space]
        let tail = String(content[content.index(after: space)...])
        guard !tail.isEmpty, !tail.contains(where: { $0.isWhitespace }) else { return nil }
        let opens = owner.indices.filter { owner[$0] == "(" }
        let closes = owner.indices.filter { owner[$0] == ")" }
        if opens.isEmpty && closes.isEmpty {
            className = String(owner)
            category = nil
        } else {
            guard opens.count == 1, closes.count == 1,
                  let open = opens.first, let close = closes.first,
                  open != owner.startIndex, open < close,
                  close == owner.index(before: owner.endIndex),
                  owner.index(after: open) != close else { return nil }
            className = String(owner[..<open])
            category = String(owner[owner.index(after: open)..<close])
        }
        isClassMethod = sign == "+"
        selector = tail
    }
}
