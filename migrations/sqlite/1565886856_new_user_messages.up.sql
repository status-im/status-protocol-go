DROP TABLE user_messages;

CREATE TABLE user_messages (
    id BLOB PRIMARY KEY ON CONFLICT IGNORE,
    sig_public_key BLOB NOT NULL, -- sender public key
    recipient BLOB,
    chat_id VARCHAR NOT NULL,
    content_type VARCHAR,
    message_type VARCHAR,
    text TEXT,
    clock INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,
    content_chat_id TEXT,
    content_text TEXT,
    flags INT NOT NULL DEFAULT 0
);

CREATE INDEX idx_sig_public_key ON user_messages(sig_public_key);
CREATE INDEX idx_chat_id ON user_messages(chat_id);
CREATE INDEX idx_timestamp ON user_messages(timestamp);
