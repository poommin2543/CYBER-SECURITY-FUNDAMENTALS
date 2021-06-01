import textract
text = textract.process('example.pdf', method='pdfminer')
print(text)