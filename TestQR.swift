// Generates PUBLIC SYNTHETIC test data only. No real credentials.
import Foundation
import CoreImage
import AppKit
@main struct TestQR {
    static func main() throws {
        func n(_ field: UInt8, _ value: UInt8) -> Data { Data([field * 8, value]) }
        func b(_ field: UInt8, _ data: Data) -> Data { Data([field * 8 + 2, UInt8(data.count)]) + data }
        let record = b(1, Data("12345678901234567890".utf8)) + b(2, Data("Synthetic test only".utf8)) + b(3, Data("RFC 6238".utf8)) + n(4, 1) + n(5, 1) + n(6, 2)
        let payload = b(1, record) + n(2, 1) + n(3, 1)
        var url = URLComponents(); url.scheme = "otpauth-migration"; url.host = "offline"
        url.queryItems = [URLQueryItem(name: "data", value: payload.base64EncodedString())]
        let filter = CIFilter(name: "CIQRCodeGenerator")!
        filter.setValue(Data(url.string!.utf8), forKey: "inputMessage")
        filter.setValue("M", forKey: "inputCorrectionLevel")
        let image = filter.outputImage!.transformed(by: CGAffineTransform(scaleX: 10, y: 10))
        let cg = CIContext().createCGImage(image, from: image.extent)!
        let rep = NSBitmapImageRep(cgImage: cg)
        try rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: "/tmp/codebar-synthetic.png"))
        print("Created /tmp/codebar-synthetic.png (PUBLIC SYNTHETIC account)")
    }
}
