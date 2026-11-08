import Foundation
import XCTest
@testable import MacScope

final class RegenerationNominalOrderingTests: XCTestCase {
    func testEquivalentTypeInventoriesProduceIdenticalFilesRegardlessOfOrder() throws {
        let first = RegenerationNominalTypeInput(name: "Shared", module: "A", language: .swift,
            kind: .struct, fields: [.init(name: "first", recoveredType: "Int", mutable: true)])
        let second = RegenerationNominalTypeInput(name: "Shared", module: "A", language: .swift,
            kind: .struct, fields: [.init(name: "second", recoveredType: "String", mutable: false)])
        let third = RegenerationNominalTypeInput(name: "Other", module: nil, language: .objc,
            kind: .class, fields: [])
        XCTAssertEqual(try RegenerationNominalRenderer.render([first, second, third]),
                       try RegenerationNominalRenderer.render([third, second, first]))
    }
}
