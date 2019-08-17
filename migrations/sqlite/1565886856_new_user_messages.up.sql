DROP TABLE user_messages;

CREATE TABLE user_messages (
    id BLOB PRIMARY KEY ON CONFLICT IGNORE,
    sig_public_key BLOB NOT NULL,
    chat_id VARCHAR NOT NULL,
    recipient BLOB,
    clock INTEGER NOT NULL,
    timestamp INTEGER NOT NULL,
    data BLOB NOT NULL
);

CREATE INDEX idx_sig_public_key ON user_messages(sig_public_key);
CREATE INDEX idx_chat_id ON user_messages(chat_id);
CREATE INDEX idx_timestamp ON user_messages(timestamp);