const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');

const db = new sqlite3.Database('./homework.db', (err) => {
  if (err) {
    console.error('数据库连接失败:', err.message);
  } else {
    console.log('已连接到 SQLite 数据库');
  }
});

// 初始化数据库表
function initDatabase() {
  db.serialize(() => {
    // 教师表
    db.run(`CREATE TABLE IF NOT EXISTS teachers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      name TEXT NOT NULL,
      created_at DATETIME DEFAULT (datetime('now', 'localtime'))
    )`);

    // 班级表
    db.run(`CREATE TABLE IF NOT EXISTS classes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      teacher_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      is_deleted INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT (datetime('now', 'localtime')),
      FOREIGN KEY (teacher_id) REFERENCES teachers(id)
    )`, (err) => {
      // 检查是否需要添加is_deleted字段
      db.all("PRAGMA table_info(classes)", (err, columns) => {
        if (err) {
          console.error('检查classes表结构失败:', err);
          return;
        }

        const hasIsDeleted = columns.some(col => col.name === 'is_deleted');

        if (!hasIsDeleted) {
          console.log('开始迁移classes表，添加is_deleted字段...');
          db.run(`ALTER TABLE classes ADD COLUMN is_deleted INTEGER DEFAULT 0`, (err) => {
            if (err) {
              console.error('添加is_deleted字段失败:', err);
            } else {
              console.log('已添加is_deleted字段到classes表');
            }
          });
        }
      });
    });

    // 学生表
    db.run(`CREATE TABLE IF NOT EXISTS students (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      class_id INTEGER NOT NULL,
      student_id TEXT NOT NULL,
      name TEXT NOT NULL,
      password TEXT,
      created_at DATETIME DEFAULT (datetime('now', 'localtime')),
      FOREIGN KEY (class_id) REFERENCES classes(id),
      UNIQUE(class_id, student_id)
    )`, (err) => {
      // 检查是否需要添加password字段
      db.all("PRAGMA table_info(students)", (err, columns) => {
        if (err) {
          console.error('检查students表结构失败:', err);
          return;
        }

        const hasPassword = columns.some(col => col.name === 'password');

        if (!hasPassword) {
          console.log('开始迁移students表，添加password字段...');
          db.run(`ALTER TABLE students ADD COLUMN password TEXT`, (err) => {
            if (err) {
              console.error('添加password字段失败:', err);
            } else {
              console.log('已添加password字段到students表');
              // 设置默认密码为123456
              const defaultPwd = bcrypt.hashSync('123456', 10);
              db.run(`UPDATE students SET password = ? WHERE password IS NULL`, [defaultPwd], (err) => {
                if (err) console.error('设置默认密码失败:', err);
                else console.log('已为现有学生设置默认密码: 123456');
              });
            }
          });
        }
      });
    });

    // 作业密码表（支持临时作业，class_id可以为null）
    db.run(`CREATE TABLE IF NOT EXISTS assignments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      teacher_id INTEGER NOT NULL,
      class_id INTEGER,
      password TEXT NOT NULL,
      deadline DATETIME NOT NULL,
      assignment_name TEXT NOT NULL,
      description TEXT,
      is_temp INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT (datetime('now', 'localtime')),
      FOREIGN KEY (teacher_id) REFERENCES teachers(id),
      FOREIGN KEY (class_id) REFERENCES classes(id)
    )`, (err) => {
      // 无论表是否存在，都检查字段
      db.all("PRAGMA table_info(assignments)", (err, columns) => {
        if (err) {
          console.error('检查assignments表结构失败:', err);
          return;
        }

        const hasTeacherId = columns.some(col => col.name === 'teacher_id');
        const hasIsTemp = columns.some(col => col.name === 'is_temp');
        const hasDescription = columns.some(col => col.name === 'description');
        const classIdNotNull = columns.find(col => col.name === 'class_id')?.notnull === 1;

        // 如果缺少必要字段，需要迁移
        if (!hasTeacherId || !hasIsTemp || !hasDescription || classIdNotNull) {
          console.log('开始迁移assignments表，添加description字段...');
          db.serialize(() => {
            // 如果只是缺少 description 字段，直接添加
            if (hasTeacherId && hasIsTemp && !classIdNotNull && !hasDescription) {
              db.run(`ALTER TABLE assignments ADD COLUMN description TEXT`, (err) => {
                if (err) {
                  console.error('添加description字段失败:', err);
                } else {
                  console.log('已添加description字段到assignments表');
                }
              });
            } else {
              // 需要重建表
              // 创建新表
              db.run(`CREATE TABLE IF NOT EXISTS assignments_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                teacher_id INTEGER NOT NULL,
                class_id INTEGER,
                password TEXT NOT NULL,
                deadline DATETIME NOT NULL,
                assignment_name TEXT NOT NULL,
                description TEXT,
                is_temp INTEGER DEFAULT 0,
                created_at DATETIME DEFAULT (datetime('now', 'localtime')),
                FOREIGN KEY (teacher_id) REFERENCES teachers(id),
                FOREIGN KEY (class_id) REFERENCES classes(id)
              )`);

              // 从旧表复制数据（通过class_id关联获取teacher_id）
              db.run(`INSERT INTO assignments_new (id, teacher_id, class_id, password, deadline, assignment_name, description, is_temp, created_at)
                SELECT a.id, c.teacher_id, a.class_id, a.password, a.deadline, a.assignment_name, NULL, 0, a.created_at
                FROM assignments a
                JOIN classes c ON a.class_id = c.id`, (err) => {
                  if (err) {
                    console.error('数据迁移失败:', err);
                    return;
                  }

                  // 删除旧表
                  db.run(`DROP TABLE assignments`, (err) => {
                    if (err) {
                      console.error('删除旧表失败:', err);
                      return;
                    }

                    // 重命名新表
                    db.run(`ALTER TABLE assignments_new RENAME TO assignments`, (err) => {
                      if (err) {
                        console.error('重命名表失败:', err);
                      } else {
                        console.log('assignments表迁移完成');
                      }
                    });
                  });
                });
            }
          });
        }
      });
    });

    // 上传记录表
    db.run(`CREATE TABLE IF NOT EXISTS uploads (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      assignment_id INTEGER NOT NULL,
      student_id TEXT NOT NULL,
      filename TEXT NOT NULL,
      original_filename TEXT,
      upload_time DATETIME DEFAULT (datetime('now', 'localtime')),
      ip_address TEXT,
      FOREIGN KEY (assignment_id) REFERENCES assignments(id)
    )`, (err) => {
      // 检查是否需要添加字段
      db.all("PRAGMA table_info(uploads)", (err, columns) => {
        if (err) {
          console.error('检查uploads表结构失败:', err);
          return;
        }

        const hasIpAddress = columns.some(col => col.name === 'ip_address');
        const hasOriginalFilename = columns.some(col => col.name === 'original_filename');

        if (!hasIpAddress) {
          console.log('开始迁移uploads表，添加ip_address字段...');
          db.run(`ALTER TABLE uploads ADD COLUMN ip_address TEXT`, (err) => {
            if (err) {
              console.error('添加ip_address字段失败:', err);
            } else {
              console.log('已添加ip_address字段到uploads表');
            }
          });
        }

        if (!hasOriginalFilename) {
          console.log('开始迁移uploads表，添加original_filename字段...');
          db.run(`ALTER TABLE uploads ADD COLUMN original_filename TEXT`, (err) => {
            if (err) {
              console.error('添加original_filename字段失败:', err);
            } else {
              console.log('已添加original_filename字段到uploads表');
            }
          });
        }
      });
    });

    // 管理员表
    db.run(`CREATE TABLE IF NOT EXISTS admins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      name TEXT NOT NULL,
      created_at DATETIME DEFAULT (datetime('now', 'localtime'))
    )`);

    // 教学资源表
    db.run(`CREATE TABLE IF NOT EXISTS resources (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      teacher_id INTEGER NOT NULL,
      resource_name TEXT NOT NULL,
      resource_type TEXT NOT NULL,
      file_path TEXT NOT NULL,
      file_size INTEGER DEFAULT 0,
      is_folder INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT (datetime('now', 'localtime')),
      FOREIGN KEY (teacher_id) REFERENCES teachers(id)
    )`);

    // 共享码表（重新设计支持资源共享）
    db.run(`CREATE TABLE IF NOT EXISTS shares (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      share_code TEXT UNIQUE NOT NULL,
      teacher_id INTEGER NOT NULL,
      share_type TEXT NOT NULL,
      resource_data TEXT,
      share_name TEXT,
      description TEXT,
      access_count INTEGER DEFAULT 0,
      max_access INTEGER DEFAULT 0,
      expire_at DATETIME,
      created_at DATETIME DEFAULT (datetime('now', 'localtime')),
      FOREIGN KEY (teacher_id) REFERENCES teachers(id)
    )`, (err) => {
      // 检查是否需要添加新字段（兼容旧表）
      db.all("PRAGMA table_info(shares)", (err, columns) => {
        if (err) {
          console.error('检查shares表结构失败:', err);
          return;
        }

        const hasResourceData = columns.some(col => col.name === 'resource_data');
        const hasShareName = columns.some(col => col.name === 'share_name');

        if (!hasResourceData) {
          db.run(`ALTER TABLE shares ADD COLUMN resource_data TEXT`, (err) => {
            if (err) console.error('添加resource_data字段失败:', err);
            else console.log('已添加resource_data字段到shares表');
          });
        }

        if (!hasShareName) {
          db.run(`ALTER TABLE shares ADD COLUMN share_name TEXT`, (err) => {
            if (err) console.error('添加share_name字段失败:', err);
            else console.log('已添加share_name字段到shares表');
          });
        }
      });
    });

    // 班级共享表（教师共享资源给班级）
    db.run(`CREATE TABLE IF NOT EXISTS class_shares (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      teacher_id INTEGER NOT NULL,
      class_id INTEGER NOT NULL,
      share_type TEXT NOT NULL,
      resource_path TEXT NOT NULL,
      share_name TEXT NOT NULL,
      description TEXT,
      created_at DATETIME DEFAULT (datetime('now', 'localtime')),
      FOREIGN KEY (teacher_id) REFERENCES teachers(id),
      FOREIGN KEY (class_id) REFERENCES classes(id)
    )`);

    // 创建一个默认教师账号（用户名: teacher, 密码: 123456）
    const defaultPassword = bcrypt.hashSync('123456', 10);
    db.run(`INSERT OR IGNORE INTO teachers (username, password, name) VALUES (?, ?, ?)`,
      ['teacher', defaultPassword, '默认教师'],
      (err) => {
        if (err) {
          console.log('默认教师账号已存在或创建失败');
        } else {
          console.log('已创建默认教师账号 - 用户名: teacher, 密码: 123456');
        }
      }
    );

    // 创建默认管理员账号（用户名: admin, 密码: admin123）
    const adminPassword = bcrypt.hashSync('admin123', 10);
    db.run(`INSERT OR IGNORE INTO admins (username, password, name) VALUES (?, ?, ?)`,
      ['admin', adminPassword, '系统管理员'],
      (err) => {
        if (err) {
          console.log('默认管理员账号已存在或创建失败');
        } else {
          console.log('已创建默认管理员账号 - 用户名: admin, 密码: admin123');
        }
      }
    );
  });
}

module.exports = { db, initDatabase };
