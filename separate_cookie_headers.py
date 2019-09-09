from burp import IBurpExtender
from burp import IHttpListener
from java.io import PrintWriter
import re


class BurpExtender(IBurpExtender, IHttpListener):

    def registerExtenderCallbacks(self, callbacks):
        self._helpers = callbacks.getHelpers()
        self._stdout = PrintWriter(callbacks.getStdout(), True)
        callbacks.setExtensionName("Separate cookie headers");
        callbacks.registerHttpListener(self)
        return

    def processHttpMessage(self, toolFlag, messageIsRequest, currentRequest):
        if not messageIsRequest:
            return

        requestInfo = self._helpers.analyzeRequest(currentRequest)
        bodyBytes = currentRequest.getRequest()[requestInfo.getBodyOffset():]
        bodyStr = self._helpers.bytesToString(bodyBytes)

        headers = requestInfo.getHeaders()
        newHeaders = []
        for header in list(headers):
            if re.search('[Cc]ookie', header):
                header = re.sub('[Cc]ookie.*?:', '', header)
                for cookie in header.split(';'):
                    trimmed = cookie.strip('')
                    if trimmed:
                        newHeaders.append('Cookie: ' + trimmed + ';')
            else:
                newHeaders.append(header)

        newRequest = self._helpers.buildHttpMessage(newHeaders, bodyStr)
        currentRequest.setRequest(newRequest)
        self._stdout.println("Out: " + newRequest)

