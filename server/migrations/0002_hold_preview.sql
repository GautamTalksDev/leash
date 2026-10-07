-- Holds show the approver what they are approving: query string, extracted SQL or GraphQL, and the body, capped at 2 KB.
ALTER TABLE holds ADD COLUMN preview TEXT;
