package com.anm.digisign.model;

public class SignRecord {
    private final String time;
    private final String docName;
    private final String status;

    public SignRecord(String time, String docName, String status) {
        this.time = time;
        this.docName = docName;
        this.status = status;
    }

    public String getTime() { return time; }
    public String getDocName() { return docName; }
    public String getStatus() { return status; }
}