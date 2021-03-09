package com.icicibank.apimngmnt.HybridEncDec;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.message.MessageContext;

public class ContentLogger {
  private MessageContext msgContext;
  
  private ExecutionContext execContext;
  
  public ContentLogger() {}
  
  public ContentLogger(MessageContext msgContext, ExecutionContext execContext) {
    this.msgContext = msgContext;
    this.execContext = execContext;
  }
  
  public void log(String variable, String value) {
    this.msgContext.setVariable(variable, value);
  }
}
