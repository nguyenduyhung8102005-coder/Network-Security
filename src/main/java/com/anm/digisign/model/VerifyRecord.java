package com.anm.digisign.model;

public class VerifyRecord {
    private final String time;
    private final String docName;
    private final String result;

    public VerifyRecord(String time, String docName, String result) {
        this.time = time;
        this.docName = docName;
        this.result = result;
    }

    public String getTime() { return time; }
    public String getDocName() { return docName; }
    public String getResult() { return result; }
}