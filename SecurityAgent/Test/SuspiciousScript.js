// Bu bir test dosyasıdır, zararlı değildir.
// SecurityAgent'ın IOC tarayıcısı tarafından tespit edilecek şüpheli kalıplar içerir.

// Şüpheli kalıp: Eval kullanımı
function obfuscatedCode() {
    var encodedString = "YWxlcnQoIkJ1IGJpciBndXZlbmxpayB0ZXN0aWRpciwgemFyYXJsaSBkZWdpbGRpcj0iKTs=";
    var decodedString = atob(encodedString);
    eval(decodedString); // Bu sadece "Bu bir guvenlik testidir, zararli degildir=" mesajını gösterir
}

// Şüpheli kalıp: Document.write
function writeHTML() {
    document.write("<div>Test content</div>");
}

// Şüpheli kalıp: ActiveXObject
function createActiveX() {
    try {
        var wshShell = new ActiveXObject("WScript.Shell");
        // Bu sadece bir test, gerçekte çalıştırılmaz
    } catch (e) {
        console.log("ActiveX objesi oluşturulamadı (bu beklenen bir durumdur)");
    }
}

// Şüpheli kalıp: XMLHttpRequest
function sendRequest() {
    var xhr = new XMLHttpRequest();
    xhr.open("GET", "https://example.com", false);
    // xhr.send(); // Bu satır yorum halinde, gerçekte istek göndermez
}

console.log("Bu dosya zararlı DEĞİLDİR. Sadece SecurityAgent'ın şüpheli kalıpları tespit etme yeteneğini test etmek için oluşturulmuştur."); 