CREATE DATABASE secure_sdlc_audit CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE USER 'audit_user'@'localhost' IDENTIFIED BY 'YourStrongPassword!';
GRANT ALL PRIVILEGES ON secure_sdlc_audit.* TO 'audit_user'@'localhost';
FLUSH PRIVILEGES;
USE secure_sdlc_audit;

CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(150),
  org_name VARCHAR(150),
  audit_date VARCHAR(50),
  mobile VARCHAR(50),
  email VARCHAR(150) NOT NULL UNIQUE,
  password_hash VARCHAR(256) NOT NULL,
  role VARCHAR(20) DEFAULT 'auditee',
  org_type VARCHAR(50),
  registered_on DATETIME DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE tokens (
  id INT AUTO_INCREMENT PRIMARY KEY,
  code VARCHAR(200) NOT NULL UNIQUE,
  purpose VARCHAR(50),
  created_by INT,
  created_on DATETIME DEFAULT CURRENT_TIMESTAMP,
  used TINYINT(1) DEFAULT 0,
  CONSTRAINT fk_tokens_created_by FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE data_submission (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT,
  assets_filename VARCHAR(300),
  checklist_filename VARCHAR(300),
  auditees_count INT,
  auditee_names_json TEXT,
  submitted_on DATETIME DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_submission_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE control_evidence (
  id INT AUTO_INCREMENT PRIMARY KEY,
  user_id INT,
  submission_id INT,
  control_number INT,
  status VARCHAR(50),
  image_filename VARCHAR(300),
  notes TEXT,
  submitted_on DATETIME DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_evidence_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  CONSTRAINT fk_evidence_submission FOREIGN KEY (submission_id) REFERENCES data_submission(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
