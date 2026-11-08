import Foundation

enum ObjCMethodOwnerIndex {
    struct Candidate: Equatable, Sendable {
        var owner: ObjCMethodOwner
        var method: ObjCMethod
    }

    static func owner(
        implementation: UInt64,
        classes: [ObjCClass],
        categories: [ObjCCategory]
    ) -> ObjCMethodOwnerLookup {
        struct Key: Hashable {
            var owner: ObjCMethodOwner
            var selector: String
        }
        var seen: Set<Key> = []
        var matches: [ObjCMethodOwnerLookup.Match] = []

        func collect(_ methods: [ObjCMethod], owner: ObjCMethodOwner) {
            for var method in methods where method.implementation == implementation {
                guard seen.insert(.init(owner: owner, selector: method.selector)).inserted else {
                    continue
                }
                method.isClassMethod = owner.isClassMethod
                matches.append(.init(owner: owner, method: method))
            }
        }

        for objcClass in classes {
            let container = ObjCMethodOwner.Container.objcClass(name: objcClass.name)
            collect(objcClass.classMethods, owner: .init(container: container, isClassMethod: true))
            collect(objcClass.instanceMethods, owner: .init(container: container, isClassMethod: false))
        }
        for category in categories {
            let container = ObjCMethodOwner.Container.category(
                name: category.name,
                className: category.className
            )
            collect(category.classMethods, owner: .init(container: container, isClassMethod: true))
            collect(category.instanceMethods, owner: .init(container: container, isClassMethod: false))
        }

        switch matches.count {
        case 0: return .none
        case 1: return .unique(matches[0])
        default: return .ambiguous(matches.sorted { $0.displayName < $1.displayName })
        }
    }

    /// Returns all methods at the first hierarchy level that declares `selector`.
    /// This is prototype evidence only; it does not select a runtime implementation.
    static func methodsInStaticScope(
        selector: String,
        receiverClassName: String,
        isClassMethod: Bool,
        classes: [ObjCClass],
        categories: [ObjCCategory]
    ) -> [Candidate] {
        let classesByName = Dictionary(grouping: classes, by: \.name)
        var visited: Set<String> = []
        var className: String? = receiverClassName

        while let currentName = className, visited.insert(currentName).inserted {
            var candidates: [Candidate] = []
            if let records = classesByName[currentName] {
                for record in records {
                    let methods = isClassMethod ? record.classMethods : record.instanceMethods
                    let owner = ObjCMethodOwner(
                        container: .objcClass(name: currentName),
                        isClassMethod: isClassMethod
                    )
                    candidates += methods
                        .filter { $0.selector == selector }
                        .map { Candidate(owner: owner, method: $0) }
                }
            }
            for category in categories where category.className == currentName {
                let methods = isClassMethod ? category.classMethods : category.instanceMethods
                let owner = ObjCMethodOwner(
                    container: .category(name: category.name, className: currentName),
                    isClassMethod: isClassMethod
                )
                candidates += methods
                    .filter { $0.selector == selector }
                    .map { Candidate(owner: owner, method: $0) }
            }
            let canonical = deduplicated(candidates)
            if !canonical.isEmpty { return canonical }

            let superNames = (classesByName[currentName] ?? [])
                .compactMap(\.superclassName)
                .filter { !$0.isEmpty }
            guard Set(superNames).count == 1 else { return [] }
            className = superNames.first
        }
        return []
    }

    static func receiverClassName(for owner: ObjCMethodOwner) -> String {
        switch owner.container {
        case .objcClass(let name): return name
        case .category(_, let className): return className
        }
    }

    private static func deduplicated(_ candidates: [Candidate]) -> [Candidate] {
        struct Key: Hashable {
            var owner: ObjCMethodOwner
            var selector: String
            var typeEncoding: String?
            var implementation: UInt64?
        }
        var seen: Set<Key> = []
        return candidates.filter {
            seen.insert(.init(
                owner: $0.owner,
                selector: $0.method.selector,
                typeEncoding: $0.method.typeEncoding,
                implementation: $0.method.implementation
            )).inserted
        }
        .sorted {
            ($0.owner.displayName, $0.method.selector, $0.method.implementation ?? 0)
                < ($1.owner.displayName, $1.method.selector, $1.method.implementation ?? 0)
        }
    }
}
