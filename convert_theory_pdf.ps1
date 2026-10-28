$word = New-Object -ComObject Word.Application
$word.Visible = $false
try {
    $docxPath = "C:\IS project\PCAP_to_SQLite_Core_Theory_and_Concepts.docx"
    $pdfPath = "C:\IS project\PCAP_to_SQLite_Core_Theory_and_Concepts.pdf"
    $doc = $word.Documents.Open($docxPath)
    # 17 is wdFormatPDF
    $doc.SaveAs([ref]$pdfPath, [ref]17)
    $doc.Close()
    Write-Output "PDF converted successfully: $pdfPath"
} catch {
    Write-Error $_
} finally {
    $word.Quit()
    [System.Runtime.Interopservices.Marshal]::ReleaseComObject($word) | Out-Null
}
