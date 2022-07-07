def xcrypt(file):

    key = ord('m')

    finalData = ''
    orgFile = open(file, 'rb')
        
    data = orgFile.read()
    
    for i in data:
        xbyte = i ^ key
        finalData += chr(xbyte)
    
    finalData = finalData.encode('utf-8')

    with open(file, 'wb') as f:
        f.write(finalData)
        f.close()


