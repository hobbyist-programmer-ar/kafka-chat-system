package com.hobbyistprogrammer.kafka_chat_system.model;


import lombok.Data;
import org.springframework.data.annotation.Id;

import java.time.LocalDateTime;

@Data
public class Message {
    @Id
    Long id;
    String message;
    LocalDateTime createdAt;
    Boolean isDelivered;
    Boolean isFlagged;
    String flagReason;
}
