package org.example;
import burp.*;

public class extension implements IBurpExtender, IHttpListener {

    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        helpers = callbacks.getHelpers();
        this.callbacks=callbacks;
        callbacks.setExtensionName("Request Modifier");

        // Register this class as an HTTP listener
        callbacks.registerHttpListener(this);
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // Check if the message is a request
        if (messageIsRequest) {
            // Get the request object
            IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
            //check if url contains paramter like ?id =
            String modifiedUrl = requestInfo.getUrl() + "?=<script>alert('hello')</script>";

            // Modify the request by adding a custom header


                String request = new String(messageInfo.getRequest());
                // add a custom os command or list of commands
                byte[] modifiedRequestparam = (request + "whoami").getBytes();
                messageInfo.setRequest(modifiedRequestparam);
                 byte[] modifiedRequest = helpers.updateParameter(
                    messageInfo.getRequest(),
                    helpers.buildParameter("url", modifiedUrl, IParameter.PARAM_URL)
             );

            callbacks.printOutput("Modified URL from: " + requestInfo.getUrl() + " to: " + modifiedUrl);

            messageInfo.setRequest(modifiedRequest);

        }
    }
}