const express = require('express');
const session = require('express-session');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const os = require('os');
const { db, initDatabase } = require('./database');
const archiver = require('archiver');
const XLSX = require('xlsx');

const app = express();
const PORT = 8080;
const HOST = '0.0.0.0'

// 初始化数据库
initDatabase();

// 中间件
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: 'homework-upload-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 } // 24小时
}));

// 静态文件服务
app.use(express.static('public'));

// 创建上传目录
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// 创建教学资源目录
const resourcesDir = path.join(__dirname, 'resources');
if (!fs.existsSync(resourcesDir)) {
  fs.mkdirSync(resourcesDir, { recursive: true });
}

// 通用上传中间件（保存到临时目录，后续由路由处理移动）
const uploadMiddleware = multer({ dest: path.join(uploadsDir, 'temp') });

// ==================== 教师相关 API ====================

// 教师登录
app.post('/api/teacher/login', (req, res) => {
  const { username, password } = req.body;

  db.get('SELECT * FROM teachers WHERE username = ?', [username], (err, teacher) => {
    if (err) {
      return res.status(500).json({ success: false, message: '服务器错误' });
    }

    if (!teacher) {
      return res.json({ success: false, message: '用户名或密码错误' });
    }

    if (!bcrypt.compareSync(password, teacher.password)) {
      return res.json({ success: false, message: '用户名或密码错误' });
    }

    req.session.teacherId = teacher.id;
    req.session.teacherName = teacher.name;
    res.json({ success: true, teacher: { id: teacher.id, name: teacher.name } });
  });
});

// 读取教师白名单
function loadTeacherWhitelist() {
  const whitelistPath = path.join(__dirname, 'teachers_whitelist.txt');
  try {
    const content = fs.readFileSync(whitelistPath, 'utf-8');
    return content.split('\n').map(name => name.trim()).filter(name => name.length > 0);
  } catch (err) {
    console.error('读取教师白名单失败:', err);
    return [];
  }
}

// 教师注册
app.post('/api/teacher/register', (req, res) => {
  const { username, password, name } = req.body;

  // 验证姓名是否在白名单中
  const whitelist = loadTeacherWhitelist();
  if (!whitelist.includes(name)) {
    return res.json({ success: false, message: '您的姓名不在教师名单中，请联系管理员' });
  }

  const hashedPassword = bcrypt.hashSync(password, 10);

  db.run('INSERT INTO teachers (username, password, name) VALUES (?, ?, ?)',
    [username, hashedPassword, name],
    function(err) {
      if (err) {
        if (err.message.includes('UNIQUE')) {
          return res.json({ success: false, message: '用户名已存在' });
        }
        return res.status(500).json({ success: false, message: '注册失败' });
      }
      res.json({ success: true, message: '注册成功' });
    }
  );
});

// 教师退出登录
app.post('/api/teacher/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// 检查教师登录状态
app.get('/api/teacher/check', (req, res) => {
  if (req.session.teacherId) {
    res.json({ loggedIn: true, teacher: { id: req.session.teacherId, name: req.session.teacherName } });
  } else {
    res.json({ loggedIn: false });
  }
});

// 教师修改密码
app.post('/api/teacher/change-password', (req, res) => {
  if (!req.session.teacherId) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  const { oldPassword, newPassword } = req.body;

  if (!oldPassword || !newPassword) {
    return res.status(400).json({ success: false, message: '请填写所有信息' });
  }

  if (newPassword.length < 6) {
    return res.json({ success: false, message: '新密码长度至少6位' });
  }

  // 验证旧密码
  db.get('SELECT * FROM teachers WHERE id = ?', [req.session.teacherId], (err, teacher) => {
    if (err) {
      return res.status(500).json({ success: false, message: '服务器错误' });
    }

    if (!teacher) {
      return res.json({ success: false, message: '用户不存在' });
    }

    if (!bcrypt.compareSync(oldPassword, teacher.password)) {
      return res.json({ success: false, message: '原密码错误' });
    }

    // 更新密码
    const hashedPassword = bcrypt.hashSync(newPassword, 10);
    db.run('UPDATE teachers SET password = ? WHERE id = ?',
      [hashedPassword, req.session.teacherId],
      (err) => {
        if (err) {
          return res.status(500).json({ success: false, message: '修改密码失败' });
        }
        res.json({ success: true, message: '密码修改成功' });
      }
    );
  });
});

// ==================== 管理员相关 API ====================

// 管理员登录
app.post('/api/admin/login', (req, res) => {
  const { username, password } = req.body;

  db.get('SELECT * FROM admins WHERE username = ?', [username], (err, admin) => {
    if (err) {
      return res.status(500).json({ success: false, message: '服务器错误' });
    }

    if (!admin) {
      return res.json({ success: false, message: '用户名或密码错误' });
    }

    if (!bcrypt.compareSync(password, admin.password)) {
      return res.json({ success: false, message: '用户名或密码错误' });
    }

    req.session.adminId = admin.id;
    req.session.adminName = admin.name;
    res.json({ success: true, admin: { id: admin.id, name: admin.name } });
  });
});

// 管理员退出登录
app.post('/api/admin/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// 检查管理员登录状态
app.get('/api/admin/check', (req, res) => {
  if (req.session.adminId) {
    res.json({ loggedIn: true, admin: { id: req.session.adminId, name: req.session.adminName } });
  } else {
    res.json({ loggedIn: false });
  }
});

// 获取所有教师列表及其班级信息
app.get('/api/admin/teachers', (req, res) => {
  if (!req.session.adminId) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  // 获取所有教师
  db.all('SELECT id, username, name, created_at FROM teachers ORDER BY created_at DESC', (err, teachers) => {
    if (err) {
      return res.status(500).json({ success: false, message: '获取教师列表失败' });
    }

    // 为每个教师获取班级信息（包括已删除的）
    const teacherPromises = teachers.map(teacher => {
      return new Promise((resolve) => {
        db.all('SELECT id, name, is_deleted, created_at FROM classes WHERE teacher_id = ? ORDER BY is_deleted ASC, created_at DESC', [teacher.id], (err, classes) => {
          if (err) {
            resolve({ ...teacher, classes: [] });
          } else {
            resolve({ ...teacher, classes });
          }
        });
      });
    });

    Promise.all(teacherPromises).then(teachersWithClasses => {
      res.json({ success: true, teachers: teachersWithClasses });
    });
  });
});

// 获取系统统计信息
app.get('/api/admin/stats', (req, res) => {
  if (!req.session.adminId) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  const stats = {};

  // 获取教师总数
  db.get('SELECT COUNT(*) as count FROM teachers', (err, result) => {
    stats.teacherCount = result ? result.count : 0;

    // 获取班级总数
    db.get('SELECT COUNT(*) as count FROM classes', (err, result) => {
      stats.classCount = result ? result.count : 0;

      // 获取学生总数
      db.get('SELECT COUNT(*) as count FROM students', (err, result) => {
        stats.studentCount = result ? result.count : 0;

        // 获取作业总数
        db.get('SELECT COUNT(*) as count FROM assignments', (err, result) => {
          stats.assignmentCount = result ? result.count : 0;

          // 获取上传文件总数
          db.get('SELECT COUNT(*) as count FROM uploads', (err, result) => {
            stats.uploadCount = result ? result.count : 0;
            res.json({ success: true, stats });
          });
        });
      });
    });
  });
});

// 管理员重置教师密码
app.post('/api/admin/reset-teacher-password', (req, res) => {
  if (!req.session.adminId) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  const { teacherId, newPassword } = req.body;

  if (!teacherId || !newPassword) {
    return res.status(400).json({ success: false, message: '请填写所有信息' });
  }

  if (newPassword.length < 6) {
    return res.json({ success: false, message: '新密码长度至少6位' });
  }

  // 验证教师是否存在
  db.get('SELECT * FROM teachers WHERE id = ?', [teacherId], (err, teacher) => {
    if (err) {
      return res.status(500).json({ success: false, message: '服务器错误' });
    }

    if (!teacher) {
      return res.json({ success: false, message: '教师不存在' });
    }

    // 更新密码
    const hashedPassword = bcrypt.hashSync(newPassword, 10);
    db.run('UPDATE teachers SET password = ? WHERE id = ?',
      [hashedPassword, teacherId],
      (err) => {
        if (err) {
          return res.status(500).json({ success: false, message: '修改密码失败' });
        }
        res.json({ success: true, message: '密码重置成功' });
      }
    );
  });
});

// 管理员硬删除班级
app.delete('/api/admin/classes/:classId', (req, res) => {
  if (!req.session.adminId) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  const { classId } = req.params;

  // 获取班级信息
  db.get('SELECT * FROM classes WHERE id = ?', [classId], (err, classInfo) => {
    if (err) {
      return res.status(500).json({ success: false, message: '服务器错误' });
    }

    if (!classInfo) {
      return res.status(404).json({ success: false, message: '班级不存在' });
    }

    // 获取该班级的所有作业ID
    db.all('SELECT id FROM assignments WHERE class_id = ?', [classId], (err, assignments) => {
      if (err) {
        console.error('获取班级作业列表失败:', err);
        return res.status(500).json({ success: false, message: '删除失败' });
      }

      // 删除作业的上传记录
      const assignmentIds = assignments.map(a => a.id);
      if (assignmentIds.length > 0) {
        const placeholders = assignmentIds.map(() => '?').join(',');
        db.run(`DELETE FROM uploads WHERE assignment_id IN (${placeholders})`, assignmentIds, (err) => {
          if (err) {
            console.error('删除上传记录失败:', err);
          }
        });
      }

      // 删除作业记录
      db.run('DELETE FROM assignments WHERE class_id = ?', [classId], (err) => {
        if (err) {
          console.error('删除作业记录失败:', err);
          return res.status(500).json({ success: false, message: '删除失败' });
        }

        // 删除学生记录
        db.run('DELETE FROM students WHERE class_id = ?', [classId], (err) => {
          if (err) {
            console.error('删除学生记录失败:', err);
            return res.status(500).json({ success: false, message: '删除失败' });
          }

          // 删除班级记录
          db.run('DELETE FROM classes WHERE id = ?', [classId], (err) => {
            if (err) {
              console.error('删除班级记录失败:', err);
              return res.status(500).json({ success: false, message: '删除失败' });
            }

            // 删除文件系统中的作业目录
            if (assignmentIds.length > 0) {
              assignmentIds.forEach(assignmentId => {
                const assignmentDir = path.join(uploadsDir, `teacher_${classInfo.teacher_id}`, `assignment_${assignmentId}`);
                if (fs.existsSync(assignmentDir)) {
                  try {
                    fs.rmSync(assignmentDir, { recursive: true, force: true });
                  } catch (err) {
                    console.error('删除作业目录失败:', err);
                  }
                }
              });
            }

            res.json({ success: true, message: '班级及所有相关数据已彻底删除' });
          });
        });
      });
    });
  });
});

// ==================== 教师相关 API ====================

// 创建班级
app.post('/api/classes', (req, res) => {
  if (!req.session.teacherId) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  const { name } = req.body;

  db.run('INSERT INTO classes (teacher_id, name) VALUES (?, ?)',
    [req.session.teacherId, name],
    function(err) {
      if (err) {
        return res.status(500).json({ success: false, message: '创建班级失败' });
      }
      res.json({ success: true, classId: this.lastID });
    }
  );
});

// 获取教师的所有班级
app.get('/api/classes', (req, res) => {
  if (!req.session.teacherId) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  db.all('SELECT * FROM classes WHERE teacher_id = ? AND is_deleted = 0 ORDER BY created_at DESC',
    [req.session.teacherId],
    (err, classes) => {
      if (err) {
        return res.status(500).json({ success: false, message: '获取班级列表失败' });
      }
      res.json({ success: true, classes });
    }
  );
});

// 批量添加学生（文本格式：学号 姓名 [密码]）
app.post('/api/classes/:classId/students/batch', (req, res) => {
  if (!req.session.teacherId) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  const { classId } = req.params;
  const { studentsText, defaultPassword } = req.body;

  // 验证班级是否属于当前教师
  db.get('SELECT * FROM classes WHERE id = ? AND teacher_id = ?',
    [classId, req.session.teacherId],
    (err, classInfo) => {
      if (err || !classInfo) {
        return res.status(403).json({ success: false, message: '无权操作此班级' });
      }

      // 解析学生数据
      const lines = studentsText.trim().split('\n');
      let successCount = 0;
      let errorCount = 0;

      // 默认密码（如果没有指定则使用123456）
      const defaultPwd = defaultPassword || '123456';
      const hashedDefaultPwd = bcrypt.hashSync(defaultPwd, 10);

      const insertPromises = lines.map(line => {
        return new Promise((resolve) => {
          const parts = line.trim().split(/\s+/);
          if (parts.length >= 2) {
            const studentId = parts[0];
            const name = parts[1];
            // 如果提供了第三个参数，则作为密码
            const password = parts.length >= 3 ? bcrypt.hashSync(parts[2], 10) : hashedDefaultPwd;

            db.run('INSERT INTO students (class_id, student_id, name, password) VALUES (?, ?, ?, ?)',
              [classId, studentId, name, password],
              (err) => {
                if (err) {
                  errorCount++;
                } else {
                  successCount++;
                }
                resolve();
              }
            );
          } else {
            errorCount++;
            resolve();
          }
        });
      });

      Promise.all(insertPromises).then(() => {
        res.json({
          success: true,
          message: `成功添加 ${successCount} 名学生，${errorCount} 条记录失败`
        });
      });
    }
  );
});

// 获取班级的所有学生
app.get('/api/classes/:classId/students', (req, res) => {
  if (!req.session.teacherId) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  const { classId } = req.params;

  db.all('SELECT * FROM students WHERE class_id = ? ORDER BY student_id',
    [classId],
    (err, students) => {
      if (err) {
        return res.status(500).json({ success: false, message: '获取学生列表失败' });
      }
      res.json({ success: true, students });
    }
  );
});

// 删除单个学生
app.delete('/api/students/:studentId', (req, res) => {
  if (!req.session.teacherId) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  const { studentId } = req.params;

  // 验证学生所在班级是否属于当前教师
  db.get(`SELECT s.*, c.teacher_id FROM students s
          JOIN classes c ON s.class_id = c.id
          WHERE s.id = ?`,
    [studentId],
    (err, student) => {
      if (err) {
        return res.status(500).json({ success: false, message: '服务器错误' });
      }

      if (!student) {
        return res.status(404).json({ success: false, message: '学生不存在' });
      }

      if (student.teacher_id !== req.session.teacherId) {
        return res.status(403).json({ success: false, message: '无权删除此学生' });
      }

      // 删除学生
      db.run('DELETE FROM students WHERE id = ?', [studentId], (err) => {
        if (err) {
          console.error('删除学生失败:', err);
          return res.status(500).json({ success: false, message: '删除失败' });
        }
        res.json({ success: true, message: '学生删除成功' });
      });
    }
  );
});

// 批量删除学生
app.post('/api/students/batch-delete', (req, res) => {
  if (!req.session.teacherId) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  const { studentIds } = req.body;

  if (!studentIds || !Array.isArray(studentIds) || studentIds.length === 0) {
    return res.status(400).json({ success: false, message: '请选择要删除的学生' });
  }

  // 验证所有学生是否都属于当前教师的班级
  const placeholders = studentIds.map(() => '?').join(',');
  db.all(`SELECT s.id, c.teacher_id FROM students s
          JOIN classes c ON s.class_id = c.id
          WHERE s.id IN (${placeholders})`,
    studentIds,
    (err, students) => {
      if (err) {
        return res.status(500).json({ success: false, message: '服务器错误' });
      }

      // 检查是否所有学生都属于当前教师
      const unauthorized = students.some(s => s.teacher_id !== req.session.teacherId);
      if (unauthorized) {
        return res.status(403).json({ success: false, message: '无权删除某些学生' });
      }

      // 批量删除学生
      db.run(`DELETE FROM students WHERE id IN (${placeholders})`, studentIds, (err) => {
        if (err) {
          console.error('批量删除学生失败:', err);
          return res.status(500).json({ success: false, message: '删除失败' });
        }
        res.json({ success: true, message: `成功删除 ${studentIds.length} 名学生` });
      });
    }
  );
});

// ==================== 学生认证相关 API ====================

// 学生登录
app.post('/api/student/login', (req, res) => {
  const { studentId, password, classId } = req.body;

  if (!studentId || !password) {
    return res.json({ success: false, message: '请输入学号和密码' });
  }

  // 如果指定了班级ID，则在该班级中查找
  let query = `SELECT s.*, c.name as class_name, c.teacher_id, t.name as teacher_name
               FROM students s
               JOIN classes c ON s.class_id = c.id
               JOIN teachers t ON c.teacher_id = t.id
               WHERE s.student_id = ? AND c.is_deleted = 0`;
  let params = [studentId];

  if (classId) {
    query += ' AND s.class_id = ?';
    params.push(classId);
  }

  db.get(query, params, (err, student) => {
    if (err) {
      console.error('学生登录查询失败:', err);
      return res.status(500).json({ success: false, message: '服务器错误' });
    }

    if (!student) {
      return res.json({ success: false, message: '学号不存在' });
    }

    // 验证密码
    if (!student.password) {
      return res.json({ success: false, message: '账号未设置密码，请联系教师' });
    }

    if (!bcrypt.compareSync(password, student.password)) {
      return res.json({ success: false, message: '密码错误' });
    }

    // 保存学生登录状态
    req.session.studentLoggedIn = true;
    req.session.studentDbId = student.id;
    req.session.studentId = student.student_id;
    req.session.studentName = student.name;
    req.session.studentClassId = student.class_id;
    req.session.studentClassName = student.class_name;
    req.session.studentTeacherId = student.teacher_id;

    res.json({
      success: true,
      student: {
        id: student.id,
        studentId: student.student_id,
        name: student.name,
        className: student.class_name,
        teacherName: student.teacher_name
      }
    });
  });
});

// 检查学生登录状态
app.get('/api/student/check-login', (req, res) => {
  if (req.session.studentLoggedIn) {
    res.json({
      loggedIn: true,
      student: {
        id: req.session.studentDbId,
        studentId: req.session.studentId,
        name: req.session.studentName,
        className: req.session.studentClassName
      }
    });
  } else {
    res.json({ loggedIn: false });
  }
});

// 学生登出
app.post('/api/student/logout', (req, res) => {
  req.session.studentLoggedIn = false;
  req.session.studentDbId = null;
  req.session.studentId = null;
  req.session.studentName = null;
  req.session.studentClassId = null;
  req.session.studentClassName = null;
  req.session.studentTeacherId = null;
  res.json({ success: true });
});

// 学生修改密码
app.post('/api/student/change-password', (req, res) => {
  if (!req.session.studentLoggedIn) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  const { oldPassword, newPassword } = req.body;

  if (!oldPassword || !newPassword) {
    return res.json({ success: false, message: '请输入原密码和新密码' });
  }

  if (newPassword.length < 6) {
    return res.json({ success: false, message: '新密码至少6位' });
  }

  db.get('SELECT * FROM students WHERE id = ?', [req.session.studentDbId], (err, student) => {
    if (err || !student) {
      return res.status(500).json({ success: false, message: '服务器错误' });
    }

    const storedPassword = student.password || bcrypt.hashSync('123456', 10);

    if (!bcrypt.compareSync(oldPassword, storedPassword)) {
      return res.json({ success: false, message: '原密码错误' });
    }

    const hashedNewPassword = bcrypt.hashSync(newPassword, 10);

    db.run('UPDATE students SET password = ? WHERE id = ?',
      [hashedNewPassword, req.session.studentDbId],
      (err) => {
        if (err) {
          return res.status(500).json({ success: false, message: '修改失败' });
        }
        res.json({ success: true, message: '密码修改成功' });
      }
    );
  });
});

// 获取学生的作业任务列表
app.get('/api/student/assignments', (req, res) => {
  if (!req.session.studentLoggedIn) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  db.all(`SELECT a.*,
          (SELECT COUNT(*) FROM uploads u WHERE u.assignment_id = a.id AND u.student_id = ?) as uploaded
          FROM assignments a
          WHERE a.class_id = ?
          ORDER BY a.deadline DESC`,
    [req.session.studentId, req.session.studentClassId],
    (err, assignments) => {
      if (err) {
        return res.status(500).json({ success: false, message: '获取作业列表失败' });
      }
      res.json({ success: true, assignments });
    }
  );
});

// 获取学生的班级共享资源
app.get('/api/student/class-shares', (req, res) => {
  if (!req.session.studentLoggedIn) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  db.all(`SELECT cs.*, t.name as teacher_name
          FROM class_shares cs
          JOIN teachers t ON cs.teacher_id = t.id
          WHERE cs.class_id = ?
          ORDER BY cs.created_at DESC`,
    [req.session.studentClassId],
    (err, shares) => {
      if (err) {
        return res.status(500).json({ success: false, message: '获取共享资源失败' });
      }
      res.json({ success: true, shares });
    }
  );
});

// 获取学生自己上传的文件列表
app.get('/api/student/my-uploads', (req, res) => {
  if (!req.session.studentLoggedIn) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  db.all(`SELECT u.*, a.assignment_name, a.class_id
          FROM uploads u
          JOIN assignments a ON u.assignment_id = a.id
          WHERE u.student_id = ? AND a.class_id = ?
          ORDER BY u.upload_time DESC`,
    [req.session.studentId, req.session.studentClassId],
    (err, uploads) => {
      if (err) {
        return res.status(500).json({ success: false, message: '获取上传记录失败' });
      }
      res.json({ success: true, uploads });
    }
  );
});

// 下载学生自己上传的文件
app.get('/api/student/download-my-upload/:uploadId', (req, res) => {
  if (!req.session.studentLoggedIn) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  const { uploadId } = req.params;

  db.get(`SELECT u.*, a.teacher_id, a.class_id
          FROM uploads u
          JOIN assignments a ON u.assignment_id = a.id
          WHERE u.id = ? AND u.student_id = ?`,
    [uploadId, req.session.studentId],
    (err, upload) => {
      if (err || !upload) {
        return res.status(404).json({ success: false, message: '文件不存在' });
      }

      const filePath = path.join(uploadsDir, `teacher_${upload.teacher_id}`, `assignment_${upload.assignment_id}`, upload.filename);

      if (!fs.existsSync(filePath)) {
        return res.status(404).json({ success: false, message: '文件不存在' });
      }

      res.download(filePath, upload.filename);
    }
  );
});

// 下载班级共享的文件
app.get('/api/student/download-class-share/:shareId', (req, res) => {
  if (!req.session.studentLoggedIn) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  const { shareId } = req.params;

  db.get('SELECT * FROM class_shares WHERE id = ? AND class_id = ?',
    [shareId, req.session.studentClassId],
    (err, share) => {
      if (err || !share) {
        return res.status(404).json({ success: false, message: '共享不存在' });
      }

      const fullPath = path.join(resourcesDir, share.resource_path);

      if (!fs.existsSync(fullPath)) {
        return res.status(404).json({ success: false, message: '文件不存在' });
      }

      const stats = fs.statSync(fullPath);

      if (stats.isDirectory()) {
        // 目录打包下载
        const zipFilename = `${share.share_name}_${Date.now()}.zip`;
        res.setHeader('Content-Type', 'application/zip');
        res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(zipFilename)}"`);

        const archive = archiver('zip', { zlib: { level: 9 } });
        archive.pipe(res);
        archive.directory(fullPath, false);
        archive.finalize();
      } else {
        // 单个文件下载
        res.download(fullPath, path.basename(share.resource_path));
      }
    }
  );
});

// 学生通过登录上传文件
app.post('/api/student/upload-assignment', uploadMiddleware.single('file'), (req, res) => {
  if (!req.session.studentLoggedIn) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  const { assignmentId } = req.body;

  if (!req.file) {
    return res.json({ success: false, message: '请选择文件' });
  }

  const originalFilename = decodeFilename(req.file.originalname);

  // 验证作业是否属于学生的班级
  db.get('SELECT * FROM assignments WHERE id = ? AND class_id = ?',
    [assignmentId, req.session.studentClassId],
    (err, assignment) => {
      if (err || !assignment) {
        fs.unlinkSync(req.file.path);
        return res.status(404).json({ success: false, message: '作业不存在' });
      }

      // 检查是否过期
      if (new Date() > new Date(assignment.deadline)) {
        fs.unlinkSync(req.file.path);
        return res.json({ success: false, message: '作业已截止，无法上传' });
      }

      // 获取学生姓名
      const studentId = req.session.studentId;
      const studentName = req.session.studentName;

      // 创建目录
      const assignmentDir = path.join(uploadsDir, `teacher_${assignment.teacher_id}`, `assignment_${assignmentId}`);
      if (!fs.existsSync(assignmentDir)) {
        fs.mkdirSync(assignmentDir, { recursive: true });
      }

      // 重命名文件
      const ext = path.extname(originalFilename);
      const newFilename = `${studentId}_${studentName}${ext}`;
      const newPath = path.join(assignmentDir, newFilename);

      // 删除该学生在此作业的所有旧文件和记录
      db.all('SELECT * FROM uploads WHERE assignment_id = ? AND student_id = ?',
        [assignmentId, studentId],
        (err, existingUploads) => {
          if (existingUploads && existingUploads.length > 0) {
            existingUploads.forEach(u => {
              const oldPath = path.join(assignmentDir, u.filename);
              if (fs.existsSync(oldPath)) {
                try { fs.unlinkSync(oldPath); } catch(e) {}
              }
            });
            db.run('DELETE FROM uploads WHERE assignment_id = ? AND student_id = ?',
              [assignmentId, studentId]);
          }

          // 移动文件
          fs.renameSync(req.file.path, newPath);

          // 记录上传
          const clientIP = req.ip || req.connection.remoteAddress;
          db.run(`INSERT INTO uploads (assignment_id, student_id, filename, original_filename, ip_address) VALUES (?, ?, ?, ?, ?)`,
            [assignmentId, studentId, newFilename, originalFilename, clientIP],
            (err) => {
              if (err) {
                console.error('记录上传失败:', err);
              }
              res.json({
                success: true,
                message: '上传成功',
                filename: originalFilename
              });
            }
          );
        }
      );
    }
  );
});

// ==================== 教师班级共享相关 API ====================

// 创建班级共享
app.post('/api/class-shares', (req, res) => {
  if (!req.session.teacherId) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  const { classId, shareType, resourcePath, shareName, description } = req.body;

  if (!classId || !resourcePath || !shareName) {
    return res.json({ success: false, message: '请填写必要信息' });
  }

  // 验证班级是否属于当前教师
  db.get('SELECT * FROM classes WHERE id = ? AND teacher_id = ?',
    [classId, req.session.teacherId],
    (err, classInfo) => {
      if (err || !classInfo) {
        return res.status(403).json({ success: false, message: '无权操作此班级' });
      }

      // 验证资源路径，补全 teacher 前缀
      const teacherPrefix = `teacher_${req.session.teacherId}`;
      let actualResourcePath = resourcePath;
      if (!resourcePath.startsWith(teacherPrefix) && !resourcePath.startsWith('teacher_')) {
        actualResourcePath = path.join(teacherPrefix, resourcePath);
      }

      const fullPath = path.join(resourcesDir, actualResourcePath);
      const teacherDir = path.join(resourcesDir, teacherPrefix);
      if (!path.resolve(fullPath).startsWith(path.resolve(teacherDir)) || !fs.existsSync(fullPath)) {
        return res.json({ success: false, message: '资源不存在' });
      }

      db.run(`INSERT INTO class_shares (teacher_id, class_id, share_type, resource_path, share_name, description)
              VALUES (?, ?, ?, ?, ?, ?)`,
        [req.session.teacherId, classId, shareType || 'file', actualResourcePath, shareName, description],
        function(err) {
          if (err) {
            console.error('创建班级共享失败:', err);
            return res.status(500).json({ success: false, message: '创建失败' });
          }
          res.json({ success: true, shareId: this.lastID, message: '共享创建成功' });
        }
      );
    }
  );
});

// 获取班级的共享列表
app.get('/api/classes/:classId/shares', (req, res) => {
  if (!req.session.teacherId) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  const { classId } = req.params;

  db.all(`SELECT * FROM class_shares WHERE class_id = ? AND teacher_id = ? ORDER BY created_at DESC`,
    [classId, req.session.teacherId],
    (err, shares) => {
      if (err) {
        return res.status(500).json({ success: false, message: '获取共享列表失败' });
      }
      res.json({ success: true, shares });
    }
  );
});

// 删除班级共享
app.delete('/api/class-shares/:shareId', (req, res) => {
  if (!req.session.teacherId) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  const { shareId } = req.params;

  db.run('DELETE FROM class_shares WHERE id = ? AND teacher_id = ?',
    [shareId, req.session.teacherId],
    function(err) {
      if (err) {
        return res.status(500).json({ success: false, message: '删除失败' });
      }
      if (this.changes === 0) {
        return res.status(404).json({ success: false, message: '共享不存在' });
      }
      res.json({ success: true, message: '删除成功' });
    }
  );
});

// 重置学生密码（教师操作）
app.post('/api/students/:studentId/reset-password', (req, res) => {
  if (!req.session.teacherId) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  const { studentId } = req.params;
  const { newPassword } = req.body;

  const password = newPassword || '123456';

  // 验证学生是否属于当前教师的班级
  db.get(`SELECT s.* FROM students s
          JOIN classes c ON s.class_id = c.id
          WHERE s.id = ? AND c.teacher_id = ? AND c.is_deleted = 0`,
    [parseInt(studentId), req.session.teacherId],
    (err, student) => {
      if (err) {
        console.error('重置密码查询错误:', err);
        return res.status(500).json({ success: false, message: '服务器错误' });
      }
      if (!student) {
        return res.status(403).json({ success: false, message: '学生不存在或无权操作' });
      }

      const hashedPassword = bcrypt.hashSync(password, 10);

      db.run('UPDATE students SET password = ? WHERE id = ?',
        [hashedPassword, studentId],
        (err) => {
          if (err) {
            return res.status(500).json({ success: false, message: '重置失败' });
          }
          res.json({ success: true, message: `密码已重置为: ${password}` });
        }
      );
    }
  );
});

// 导出班级作业提交情况为 Excel
app.get('/api/classes/:classId/export', (req, res) => {
  if (!req.session.teacherId) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  const { classId } = req.params;

  // 验证班级是否属于当前教师
  db.get('SELECT * FROM classes WHERE id = ? AND teacher_id = ?',
    [classId, req.session.teacherId],
    (err, classInfo) => {
      if (err) {
        return res.status(500).json({ success: false, message: '服务器错误' });
      }

      if (!classInfo) {
        return res.status(404).json({ success: false, message: '班级不存在或无权操作' });
      }

      // 获取班级所有学生
      db.all('SELECT * FROM students WHERE class_id = ? ORDER BY student_id',
        [classId],
        (err, students) => {
          if (err) {
            return res.status(500).json({ success: false, message: '获取学生列表失败' });
          }

          // 获取班级所有作业
          db.all('SELECT * FROM assignments WHERE class_id = ? ORDER BY created_at',
            [classId],
            (err, assignments) => {
              if (err) {
                return res.status(500).json({ success: false, message: '获取作业列表失败' });
              }

              if (assignments.length === 0) {
                return res.status(404).json({ success: false, message: '该班级暂无作业' });
              }

              // 获取所有作业的上传记录
              const assignmentIds = assignments.map(a => a.id);
              const placeholders = assignmentIds.map(() => '?').join(',');

              db.all(`SELECT * FROM uploads WHERE assignment_id IN (${placeholders})`,
                assignmentIds,
                (err, uploads) => {
                  if (err) {
                    return res.status(500).json({ success: false, message: '获取上传记录失败' });
                  }

                  // 构建数据结构：学生 -> 作业 -> 上传记录
                  const uploadMap = {};
                  uploads.forEach(upload => {
                    const key = `${upload.student_id}_${upload.assignment_id}`;
                    uploadMap[key] = upload;
                  });

                  // 构建 Excel 数据
                  const excelData = [];

                  // 表头
                  const headers = ['学号', '姓名'];
                  assignments.forEach(a => {
                    headers.push(a.assignment_name);
                    headers.push('上传IP');
                  });
                  headers.push('已提交数', '总作业数', '完成率');
                  excelData.push(headers);

                  // 数据行
                  students.forEach(student => {
                    const row = [student.student_id, student.name];
                    let submittedCount = 0;

                    assignments.forEach(assignment => {
                      const key = `${student.student_id}_${assignment.id}`;
                      const upload = uploadMap[key];

                      if (upload) {
                        // 格式化提交时间
                        const uploadTime = new Date(upload.upload_time);
                        row.push(uploadTime.toLocaleString('zh-CN'));
                        // 添加IP地址
                        row.push(upload.ip_address || '-');
                        submittedCount++;
                      } else {
                        row.push('未提交');
                        row.push('-');
                      }
                    });

                    const totalAssignments = assignments.length;
                    const completionRate = ((submittedCount / totalAssignments) * 100).toFixed(1) + '%';

                    row.push(submittedCount, totalAssignments, completionRate);
                    excelData.push(row);
                  });

                  // 创建工作簿和工作表
                  const wb = XLSX.utils.book_new();
                  const ws = XLSX.utils.aoa_to_sheet(excelData);

                  // 设置列宽
                  const colWidths = [
                    { wch: 12 }, // 学号
                    { wch: 10 }, // 姓名
                  ];
                  assignments.forEach(() => {
                    colWidths.push({ wch: 20 }); // 作业列（提交时间）
                    colWidths.push({ wch: 15 }); // IP地址列
                  });
                  colWidths.push({ wch: 10 }); // 已提交数
                  colWidths.push({ wch: 10 }); // 总作业数
                  colWidths.push({ wch: 10 }); // 完成率
                  ws['!cols'] = colWidths;

                  // 添加工作表到工作簿
                  XLSX.utils.book_append_sheet(wb, ws, '作业提交情况');

                  // 生成 Excel 文件
                  const excelBuffer = XLSX.write(wb, { type: 'buffer', bookType: 'xlsx' });

                  // 设置响应头
                  const filename = `${classInfo.name}_作业提交情况_${new Date().toISOString().slice(0, 10)}.xlsx`;
                  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
                  res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(filename)}"`);

                  // 发送文件
                  res.send(excelBuffer);
                }
              );
            }
          );
        }
      );
    }
  );
});

// 教师软删除班级
app.delete('/api/classes/:classId', (req, res) => {
  if (!req.session.teacherId) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  const { classId } = req.params;

  // 验证班级是否属于当前教师
  db.get('SELECT * FROM classes WHERE id = ? AND teacher_id = ?',
    [classId, req.session.teacherId],
    (err, classInfo) => {
      if (err) {
        return res.status(500).json({ success: false, message: '服务器错误' });
      }

      if (!classInfo) {
        return res.status(404).json({ success: false, message: '班级不存在或无权操作' });
      }

      // 软删除班级（设置is_deleted为1）
      db.run('UPDATE classes SET is_deleted = 1 WHERE id = ?', [classId], (err) => {
        if (err) {
          console.error('软删除班级失败:', err);
          return res.status(500).json({ success: false, message: '删除失败' });
        }
        res.json({ success: true, message: '班级已删除' });
      });
    }
  );
});

// 创建作业密码
app.post('/api/assignments', (req, res) => {
  if (!req.session.teacherId) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  const { classId, password, deadline, assignmentName, description } = req.body;

  // 验证班级是否属于当前教师
  db.get('SELECT * FROM classes WHERE id = ? AND teacher_id = ?',
    [classId, req.session.teacherId],
    (err, classInfo) => {
      if (err || !classInfo) {
        return res.status(403).json({ success: false, message: '无权操作此班级' });
      }

      // 检查密码是否与所有教师的有效作业（未截止的）重复
      const now = new Date().toISOString();
      db.get(`SELECT a.assignment_name, a.deadline, t.name as teacher_name
              FROM assignments a
              LEFT JOIN teachers t ON a.teacher_id = t.id
              WHERE a.password = ? AND a.deadline > ?`,
        [password, now],
        (err, duplicateAssignment) => {
          if (err) {
            console.error('检查密码重复失败:', err);
            return res.status(500).json({ success: false, message: '创建作业失败' });
          }

          if (duplicateAssignment) {
            const duplicateDeadline = new Date(duplicateAssignment.deadline).toLocaleString('zh-CN');
            return res.json({
              success: false,
              message: `该密码与作业"${duplicateAssignment.assignment_name}"（截止时间：${duplicateDeadline}，教师：${duplicateAssignment.teacher_name}）重复，学生将无法区分，请修改密码`
            });
          }

          // 密码不重复，创建作业
          db.run('INSERT INTO assignments (teacher_id, class_id, password, deadline, assignment_name, description, is_temp) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [req.session.teacherId, classId, password, deadline, assignmentName, description || null, 0],
            function(err) {
              if (err) {
                return res.status(500).json({ success: false, message: '创建作业失败' });
              }
              res.json({ success: true, assignmentId: this.lastID });
            }
          );
        }
      );
    }
  );
});

// 创建临时作业（不需要班级）
app.post('/api/assignments/temp', (req, res) => {
  if (!req.session.teacherId) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  const { password, deadline, assignmentName, description } = req.body;

  if (!password || !deadline || !assignmentName) {
    return res.status(400).json({ success: false, message: '请填写所有信息' });
  }

  // 检查密码是否与所有教师的有效作业（未截止的）重复
  const now = new Date().toISOString();
  db.get(`SELECT a.assignment_name, a.deadline, t.name as teacher_name
          FROM assignments a
          LEFT JOIN teachers t ON a.teacher_id = t.id
          WHERE a.password = ? AND a.deadline > ?`,
    [password, now],
    (err, duplicateAssignment) => {
      if (err) {
        console.error('检查密码重复失败:', err);
        return res.status(500).json({ success: false, message: '创建临时作业失败' });
      }

      if (duplicateAssignment) {
        const duplicateDeadline = new Date(duplicateAssignment.deadline).toLocaleString('zh-CN');
        return res.json({
          success: false,
          message: `该密码与作业"${duplicateAssignment.assignment_name}"（截止时间：${duplicateDeadline}，教师：${duplicateAssignment.teacher_name}）重复，学生将无法区分，请修改密码`
        });
      }

      // 密码不重复，创建临时作业
      db.run('INSERT INTO assignments (teacher_id, class_id, password, deadline, assignment_name, description, is_temp) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [req.session.teacherId, null, password, deadline, assignmentName, description || null, 1],
        function(err) {
          if (err) {
            console.error('创建临时作业失败:', err);
            return res.status(500).json({ success: false, message: '创建临时作业失败' });
          }
          res.json({ success: true, assignmentId: this.lastID });
        }
      );
    }
  );
});

// 获取教师的所有临时作业
app.get('/api/assignments/temp', (req, res) => {
  if (!req.session.teacherId) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  db.all('SELECT * FROM assignments WHERE teacher_id = ? AND is_temp = 1 ORDER BY created_at DESC',
    [req.session.teacherId],
    (err, assignments) => {
      if (err) {
        return res.status(500).json({ success: false, message: '获取临时作业列表失败' });
      }
      res.json({ success: true, assignments });
    }
  );
});

// 将临时作业关联到班级
app.put('/api/assignments/:assignmentId/link-class', (req, res) => {
  if (!req.session.teacherId) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  const { assignmentId } = req.params;
  const { classId } = req.body;

  // 验证作业是否属于当前教师
  db.get('SELECT * FROM assignments WHERE id = ? AND teacher_id = ?',
    [assignmentId, req.session.teacherId],
    (err, assignment) => {
      if (err || !assignment) {
        return res.status(404).json({ success: false, message: '作业不存在' });
      }

      if (!assignment.is_temp) {
        return res.status(400).json({ success: false, message: '只能关联临时作业' });
      }

      // 验证班级是否属于当前教师
      db.get('SELECT * FROM classes WHERE id = ? AND teacher_id = ?',
        [classId, req.session.teacherId],
        (err, classInfo) => {
          if (err || !classInfo) {
            return res.status(403).json({ success: false, message: '无权操作此班级' });
          }

          // 更新作业，关联到班级，并将 is_temp 设为 0，转换为普通作业
          db.run('UPDATE assignments SET class_id = ?, is_temp = 0 WHERE id = ?',
            [classId, assignmentId],
            function(err) {
              if (err) {
                return res.status(500).json({ success: false, message: '关联失败' });
              }
              res.json({ success: true, message: '关联成功，作业已转换为普通作业' });
            }
          );
        }
      );
    }
  );
});

// 获取班级的所有作业
app.get('/api/classes/:classId/assignments', (req, res) => {
  if (!req.session.teacherId) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  const { classId } = req.params;

  db.all('SELECT * FROM assignments WHERE class_id = ? ORDER BY created_at DESC',
    [classId],
    (err, assignments) => {
      if (err) {
        return res.status(500).json({ success: false, message: '获取作业列表失败' });
      }
      res.json({ success: true, assignments });
    }
  );
});

// 查看作业提交情况
app.get('/api/assignments/:assignmentId/submissions', (req, res) => {
  if (!req.session.teacherId) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  const { assignmentId } = req.params;

  // 获取作业信息（使用LEFT JOIN支持临时作业）
  db.get(`SELECT a.*, c.teacher_id as class_teacher_id FROM assignments a
          LEFT JOIN classes c ON a.class_id = c.id
          WHERE a.id = ?`,
    [assignmentId],
    (err, assignment) => {
      if (err || !assignment) {
        return res.status(404).json({ success: false, message: '作业不存在' });
      }

      // 验证权限
      if (assignment.teacher_id !== req.session.teacherId) {
        return res.status(403).json({ success: false, message: '无权查看此作业' });
      }

      // 临时作业：直接返回所有上传记录
      if (!assignment.class_id) {
        db.all('SELECT * FROM uploads WHERE assignment_id = ? ORDER BY upload_time DESC',
          [assignmentId],
          (err, uploads) => {
            if (err) {
              return res.status(500).json({ success: false, message: '获取提交记录失败' });
            }

            // 返回临时作业的提交情况
            res.json({
              success: true,
              assignment,
              isTemp: true,
              submissions: uploads.map(u => ({
                student_id: u.student_id,
                filename: u.filename,
                uploadTime: u.upload_time,
                ipAddress: u.ip_address
              }))
            });
          }
        );
        return;
      }

      // 普通作业：获取班级所有学生和提交情况
      db.all('SELECT * FROM students WHERE class_id = ?',
        [assignment.class_id],
        (err, students) => {
          if (err) {
            return res.status(500).json({ success: false, message: '获取学生列表失败' });
          }

          // 获取已提交的作业
          db.all('SELECT * FROM uploads WHERE assignment_id = ?',
            [assignmentId],
            (err, uploads) => {
              if (err) {
                return res.status(500).json({ success: false, message: '获取提交记录失败' });
              }

              // 合并数据
              const uploadMap = {};
              uploads.forEach(upload => {
                uploadMap[upload.student_id] = upload;
              });

              const submissions = students.map(student => ({
                ...student,
                uploaded: !!uploadMap[student.student_id],
                uploadTime: uploadMap[student.student_id]?.upload_time,
                filename: uploadMap[student.student_id]?.filename,
                ipAddress: uploadMap[student.student_id]?.ip_address
              }));

              res.json({ success: true, assignment, isTemp: false, submissions });
            }
          );
        }
      );
    }
  );
});

// 批量下载作业
app.get('/api/assignments/:assignmentId/download', (req, res) => {
  if (!req.session.teacherId) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  const { assignmentId } = req.params;

  // 作业目录路径
  const assignmentDir = path.join(uploadsDir, `teacher_${req.session.teacherId}`, `assignment_${assignmentId}`);

  // 检查目录是否存在
  if (!fs.existsSync(assignmentDir)) {
    return res.status(404).json({ success: false, message: '暂无学生提交作业' });
  }

  // 检查目录是否为空
  const files = fs.readdirSync(assignmentDir);
  if (files.length === 0) {
    return res.status(404).json({ success: false, message: '暂无学生提交作业' });
  }

  // 设置响应头
  const zipFilename = `assignment_${assignmentId}_${Date.now()}.zip`;
  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(zipFilename)}"`);

  // 创建 zip 压缩流
  const archive = archiver('zip', {
    zlib: { level: 9 } // 最高压缩级别
  });

  // 错误处理
  archive.on('error', (err) => {
    console.error('压缩失败:', err);
    res.status(500).end();
  });

  // 将压缩流导向响应
  archive.pipe(res);

  // 直接压缩整个目录
  archive.directory(assignmentDir, false);

  // 完成压缩
  archive.finalize();
});

// 编辑作业
app.put('/api/assignments/:assignmentId', (req, res) => {
  if (!req.session.teacherId) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  const { assignmentId } = req.params;
  const { password, deadline, assignmentName, description } = req.body;

  if (!password || !deadline || !assignmentName) {
    return res.status(400).json({ success: false, message: '请填写所有信息' });
  }

  // 获取作业信息
  db.get('SELECT * FROM assignments WHERE id = ?', [assignmentId], (err, assignment) => {
    if (err || !assignment) {
      return res.status(404).json({ success: false, message: '作业不存在' });
    }

    if (assignment.teacher_id !== req.session.teacherId) {
      return res.status(403).json({ success: false, message: '无权修改此作业' });
    }

    // 如果修改了密码，检查新密码是否与其他有效作业重复（排除当前作业）
    if (password !== assignment.password) {
      const now = new Date().toISOString();
      db.get(`SELECT a.assignment_name, a.deadline, t.name as teacher_name
              FROM assignments a
              LEFT JOIN teachers t ON a.teacher_id = t.id
              WHERE a.password = ? AND a.deadline > ? AND a.id != ?`,
        [password, now, assignmentId],
        (err, duplicateAssignment) => {
          if (err) {
            console.error('检查密码重复失败:', err);
            return res.status(500).json({ success: false, message: '修改作业失败' });
          }

          if (duplicateAssignment) {
            const duplicateDeadline = new Date(duplicateAssignment.deadline).toLocaleString('zh-CN');
            return res.json({
              success: false,
              message: `该密码与作业"${duplicateAssignment.assignment_name}"（截止时间：${duplicateDeadline}，教师：${duplicateAssignment.teacher_name}）重复，学生将无法区分，请修改密码`
            });
          }

          // 密码不重复，更新作业
          updateAssignment();
        }
      );
    } else {
      // 密码未修改，直接更新
      updateAssignment();
    }

    function updateAssignment() {
      db.run('UPDATE assignments SET password = ?, deadline = ?, assignment_name = ?, description = ? WHERE id = ?',
        [password, deadline, assignmentName, description || null, assignmentId],
        function(err) {
          if (err) {
            console.error('更新作业失败:', err);
            return res.status(500).json({ success: false, message: '修改作业失败' });
          }
          res.json({ success: true, message: '作业修改成功' });
        }
      );
    }
  });
});

// 删除作业
app.delete('/api/assignments/:assignmentId', (req, res) => {
  if (!req.session.teacherId) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  const { assignmentId } = req.params;

  // 获取作业信息（支持临时作业）
  db.get(`SELECT * FROM assignments WHERE id = ?`,
    [assignmentId],
    (err, assignment) => {
      if (err || !assignment) {
        return res.status(404).json({ success: false, message: '作业不存在' });
      }

      if (assignment.teacher_id !== req.session.teacherId) {
        return res.status(403).json({ success: false, message: '无权删除此作业' });
      }

      // 删除数据库中的上传记录
      db.run('DELETE FROM uploads WHERE assignment_id = ?', [assignmentId], (err) => {
        if (err) {
          console.error('删除上传记录失败:', err);
          return res.status(500).json({ success: false, message: '删除失败' });
        }

        // 删除数据库中的作业记录
        db.run('DELETE FROM assignments WHERE id = ?', [assignmentId], (err) => {
          if (err) {
            console.error('删除作业记录失败:', err);
            return res.status(500).json({ success: false, message: '删除失败' });
          }

          // 删除文件系统中的作业目录
          const assignmentDir = path.join(uploadsDir, `teacher_${assignment.teacher_id}`, `assignment_${assignmentId}`);

          if (fs.existsSync(assignmentDir)) {
            try {
              fs.rmSync(assignmentDir, { recursive: true, force: true });
            } catch (err) {
              console.error('删除作业目录失败:', err);
              return res.status(500).json({ success: false, message: '删除文件失败' });
            }
          }

          res.json({ success: true, message: '作业删除成功' });
        });
      });
    }
  );
});

// ==================== 学生相关 API ====================

// 验证上传密码
app.post('/api/student/verify', (req, res) => {
  const { password } = req.body;

  // 查询作业（优先匹配未过期的作业）
  const now = new Date().toISOString();
  db.get(`SELECT a.*, c.teacher_id as class_teacher_id FROM assignments a
          LEFT JOIN classes c ON a.class_id = c.id
          WHERE a.password = ? AND a.deadline > ?
          ORDER BY a.deadline ASC
          LIMIT 1`, [password, now], (err, assignment) => {
    if (err) {
      return res.status(500).json({ success: false, message: '服务器错误' });
    }

    if (!assignment) {
      return res.json({ success: false, message: '密码错误或已过期' });
    }

    // 保存到session
    req.session.assignmentId = assignment.id;
    req.session.assignmentName = assignment.assignment_name;
    req.session.classId = assignment.class_id; // 临时作业时为null
    req.session.teacherId = assignment.teacher_id;
    req.session.isTemp = assignment.is_temp === 1;

    res.json({
      success: true,
      assignment: {
        id: assignment.id,
        name: assignment.assignment_name,
        deadline: assignment.deadline,
        description: assignment.description,
        isTemp: assignment.is_temp === 1
      }
    });
  });
});

// 配置文件上传
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    // 直接保存到对应的作业目录
    const assignmentDir = path.join(uploadsDir, `teacher_${req.session.teacherId}`, `assignment_${req.session.assignmentId}`);

    // 确保目录存在
    if (!fs.existsSync(assignmentDir)) {
      fs.mkdirSync(assignmentDir, { recursive: true });
    }

    cb(null, assignmentDir);
  },
  filename: (req, file, cb) => {
    // 使用临时文件名，在上传处理函数中重命名
    // 因为此时 req.body 可能还未完全解析
    cb(null, `temp_${Date.now()}_${Math.random().toString(36).substring(7)}_${file.originalname}`);
  }
});

const upload = multer({ storage });

// 验证学号是否在班级中（临时作业跳过验证）
app.post('/api/student/verify-student-id', (req, res) => {
  if (!req.session.assignmentId) {
    return res.status(401).json({ success: false, message: '请先验证密码' });
  }

  const { studentId } = req.body;

  if (!studentId) {
    return res.json({ success: false, message: '请输入学号' });
  }

  // 如果是临时作业，直接返回成功，不验证学号
  if (req.session.isTemp || !req.session.classId) {
    // 查询临时作业的上传历史
    db.all('SELECT * FROM uploads WHERE assignment_id = ? AND student_id = ? ORDER BY upload_time DESC',
      [req.session.assignmentId, studentId],
      (err, uploads) => {
        res.json({
          success: true,
          student: {
            student_id: studentId,
            name: '' // 临时作业没有姓名
          },
          isTemp: true,
          uploadHistory: uploads || []
        });
      }
    );
    return;
  }

  // 检查学号是否在该班级中
  db.get('SELECT * FROM students WHERE class_id = ? AND student_id = ?',
    [req.session.classId, studentId],
    (err, student) => {
      if (err) {
        return res.status(500).json({ success: false, message: '服务器错误' });
      }

      if (!student) {
        return res.json({ success: false, message: '学号不存在或不在该班级中' });
      }

      // 查询该学生在当前作业下的上传历史
      db.all('SELECT * FROM uploads WHERE assignment_id = ? AND student_id = ? ORDER BY upload_time DESC',
        [req.session.assignmentId, studentId],
        (err, uploads) => {
          if (err) {
            return res.status(500).json({ success: false, message: '查询上传历史失败' });
          }

          res.json({
            success: true,
            student: {
              student_id: student.student_id,
              name: student.name
            },
            isTemp: false,
            uploadHistory: uploads || []
          });
        }
      );
    }
  );
});

// 检查文件是否存在
app.post('/api/student/check-file', (req, res) => {
  if (!req.session.assignmentId) {
    return res.status(401).json({ success: false, message: '请先验证密码' });
  }

  const { studentId, originalFilename } = req.body;
  const ext = path.extname(originalFilename);

  // 构建文件路径
  const assignmentDir = path.join(uploadsDir, `teacher_${req.session.teacherId}`, `assignment_${req.session.assignmentId}`);

  // 临时作业：文件名只用学号
  if (req.session.isTemp || !req.session.classId) {
    const filename = `${studentId}${ext}`;
    const filePath = path.join(assignmentDir, filename);

    fs.access(filePath, fs.constants.F_OK, (err) => {
      res.json({ exists: !err });
    });
    return;
  }

  // 普通作业：查询学生姓名，文件名用"学号_姓名"
  db.get('SELECT name FROM students WHERE class_id = ? AND student_id = ?',
    [req.session.classId, studentId],
    (err, student) => {
      if (err || !student) {
        return res.json({ exists: false });
      }

      // 文件名格式：学号_姓名.扩展名
      const filename = `${studentId}_${student.name}${ext}`;
      const filePath = path.join(assignmentDir, filename);

      fs.access(filePath, fs.constants.F_OK, (err) => {
        res.json({ exists: !err });
      });
    }
  );
});

// 学生上传文件
app.post('/api/student/upload', upload.single('file'), (req, res) => {
  if (!req.session.assignmentId) {
    return res.status(401).json({ success: false, message: '请先验证密码' });
  }

  if (!req.file) {
    return res.status(400).json({ success: false, message: '请选择文件' });
  }

  const { studentId } = req.body;

  if (!studentId) {
    // 删除已上传的临时文件
    fs.unlinkSync(req.file.path);
    return res.status(400).json({ success: false, message: '请输入学号' });
  }

  const originalFilename = decodeFilename(req.file.originalname);
  const ext = path.extname(originalFilename);
  const tempFilePath = req.file.path;
  const assignmentId = req.session.assignmentId;
  const assignmentDir = path.dirname(tempFilePath);

  // 临时作业：文件名为 学号.扩展名
  if (req.session.isTemp || !req.session.classId) {
    const newFilename = `${studentId}${ext}`;
    const newFilePath = path.join(assignmentDir, newFilename);

    // 删除该学生在此作业的所有旧文件和记录
    db.all('SELECT * FROM uploads WHERE assignment_id = ? AND student_id = ?',
      [assignmentId, studentId],
      (err, existingUploads) => {
        if (existingUploads && existingUploads.length > 0) {
          existingUploads.forEach(u => {
            const oldPath = path.join(assignmentDir, u.filename);
            if (fs.existsSync(oldPath)) {
              try { fs.unlinkSync(oldPath); } catch(e) {}
            }
          });
          db.run('DELETE FROM uploads WHERE assignment_id = ? AND student_id = ?',
            [assignmentId, studentId]);
        }

        // 重命名文件
        fs.rename(tempFilePath, newFilePath, (err) => {
          if (err) {
            console.error('重命名文件失败:', err);
            try { fs.unlinkSync(tempFilePath); } catch(e) {}
            return res.status(500).json({ success: false, message: '文件上传失败' });
          }

          const clientIp = getClientIp(req);
          db.run('INSERT INTO uploads (assignment_id, student_id, filename, original_filename, ip_address) VALUES (?, ?, ?, ?, ?)',
            [assignmentId, studentId, newFilename, originalFilename, clientIp],
            function(err) {
              if (err) {
                console.error('记录上传失败:', err);
              }
              res.json({ success: true, message: '文件上传成功', filename: originalFilename });
            }
          );
        });
      }
    );
    return;
  }

  // 普通作业：需要查询学生姓名，文件名为 学号_姓名.扩展名
  db.get('SELECT name FROM students WHERE class_id = ? AND student_id = ?',
    [req.session.classId, studentId],
    (err, student) => {
      if (err || !student) {
        fs.unlinkSync(tempFilePath);
        return res.status(400).json({ success: false, message: '学号不存在' });
      }

      const newFilename = `${studentId}_${student.name}${ext}`;
      const newFilePath = path.join(assignmentDir, newFilename);

      // 删除该学生在此作业的所有旧文件和记录
      db.all('SELECT * FROM uploads WHERE assignment_id = ? AND student_id = ?',
        [assignmentId, studentId],
        (err, existingUploads) => {
          if (existingUploads && existingUploads.length > 0) {
            existingUploads.forEach(u => {
              const oldPath = path.join(assignmentDir, u.filename);
              if (fs.existsSync(oldPath)) {
                try { fs.unlinkSync(oldPath); } catch(e) {}
              }
            });
            db.run('DELETE FROM uploads WHERE assignment_id = ? AND student_id = ?',
              [assignmentId, studentId]);
          }

          // 重命名文件
          fs.rename(tempFilePath, newFilePath, (err) => {
            if (err) {
              console.error('重命名文件失败:', err);
              try { fs.unlinkSync(tempFilePath); } catch(e) {}
              return res.status(500).json({ success: false, message: '文件上传失败' });
            }

            const clientIp = getClientIp(req);
            db.run('INSERT INTO uploads (assignment_id, student_id, filename, original_filename, ip_address) VALUES (?, ?, ?, ?, ?)',
              [assignmentId, studentId, newFilename, originalFilename, clientIp],
              function(err) {
                if (err) {
                  console.error('记录上传失败:', err);
                }
                res.json({ success: true, message: '文件上传成功', filename: originalFilename });
              }
            );
          });
        }
      );
    }
  );
});

// 获取客户端真实IP地址
function getClientIp(req) {
  // 优先从代理头获取
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    // X-Forwarded-For 可能包含多个IP，取第一个
    return forwarded.split(',')[0].trim();
  }

  const realIp = req.headers['x-real-ip'];
  if (realIp) {
    return realIp;
  }

  // 直接连接的IP
  return req.connection.remoteAddress ||
         req.socket.remoteAddress ||
         req.connection.socket?.remoteAddress ||
         'unknown';
}

// ==================== 教学资源管理 API ====================

// 解码文件名（处理中文）
function decodeFilename(filename) {
  try {
    // 尝试从latin1转为utf8
    return Buffer.from(filename, 'latin1').toString('utf8');
  } catch (e) {
    return filename;
  }
}

// 配置资源文件上传
const resourceStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const teacherDir = path.join(resourcesDir, `teacher_${req.session.teacherId}`);
    if (!fs.existsSync(teacherDir)) {
      fs.mkdirSync(teacherDir, { recursive: true });
    }
    cb(null, teacherDir);
  },
  filename: (req, file, cb) => {
    // 保留原始文件名
    const originalName = decodeFilename(file.originalname);
    cb(null, originalName);
  }
});

const resourceUpload = multer({ storage: resourceStorage });

// 上传教学资源
app.post('/api/resources/upload', resourceUpload.single('file'), (req, res) => {
  if (!req.session.teacherId) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  if (!req.file) {
    return res.status(400).json({ success: false, message: '请选择文件' });
  }

  const { targetPath } = req.body;
  const teacherDir = path.join(resourcesDir, `teacher_${req.session.teacherId}`);
  const originalName = decodeFilename(req.file.originalname);
  const fileSize = req.file.size;

  let filePath = path.join(`teacher_${req.session.teacherId}`, originalName);

  // 如果指定了目标路径（子目录），将文件移动过去
  if (targetPath && targetPath !== '/' && targetPath !== '') {
    // 安全检查
    const cleanPath = targetPath.replace(/\.\./g, '');
    const targetDir = path.join(teacherDir, cleanPath);
    const resolvedTarget = path.resolve(targetDir);

    if (!resolvedTarget.startsWith(path.resolve(teacherDir))) {
      fs.unlinkSync(req.file.path);
      return res.json({ success: false, message: '目标路径不合法' });
    }

    if (!fs.existsSync(targetDir)) {
      fs.mkdirSync(targetDir, { recursive: true });
    }

    const newPath = path.join(targetDir, originalName);
    try {
      fs.renameSync(req.file.path, newPath);
      filePath = path.join(`teacher_${req.session.teacherId}`, cleanPath, originalName);
    } catch (err) {
      console.error('移动文件失败:', err);
      return res.status(500).json({ success: false, message: '上传失败' });
    }
  }

  db.run(`INSERT INTO resources (teacher_id, resource_name, resource_type, file_path, file_size, is_folder)
          VALUES (?, ?, ?, ?, ?, ?)`,
    [req.session.teacherId, originalName, 'file', filePath, fileSize, 0],
    function(err) {
      if (err) {
        console.error('记录资源失败:', err);
        return res.status(500).json({ success: false, message: '上传失败' });
      }
      res.json({
        success: true,
        resourceId: this.lastID,
        message: '资源上传成功'
      });
    }
  );
});

// 创建文件夹
app.post('/api/resources/folder', (req, res) => {
  if (!req.session.teacherId) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  const { folderName, parentPath } = req.body;

  if (!folderName || !folderName.trim()) {
    return res.json({ success: false, message: '请输入文件夹名称' });
  }

  // 安全检查：文件夹名不能包含路径分隔符
  if (folderName.includes('/') || folderName.includes('\\') || folderName.includes('..')) {
    return res.json({ success: false, message: '文件夹名称不合法' });
  }

  const teacherDir = path.join(resourcesDir, `teacher_${req.session.teacherId}`);

  // 确保教师目录存在
  if (!fs.existsSync(teacherDir)) {
    fs.mkdirSync(teacherDir, { recursive: true });
  }

  // 确定目标父目录
  let targetParent = teacherDir;
  let relativeBase = `teacher_${req.session.teacherId}`;
  if (parentPath && parentPath !== '/' && parentPath !== '') {
    const cleanParent = parentPath.replace(/\.\./g, '');
    targetParent = path.join(teacherDir, cleanParent);
    relativeBase = path.join(`teacher_${req.session.teacherId}`, cleanParent);
    const resolvedParent = path.resolve(targetParent);
    if (!resolvedParent.startsWith(path.resolve(teacherDir))) {
      return res.json({ success: false, message: '路径不合法' });
    }
    if (!fs.existsSync(targetParent)) {
      return res.json({ success: false, message: '父目录不存在' });
    }
  }

  const folderPath = path.join(targetParent, folderName.trim());

  // 检查文件夹是否已存在
  if (fs.existsSync(folderPath)) {
    return res.json({ success: false, message: '文件夹已存在' });
  }

  // 创建文件夹
  try {
    fs.mkdirSync(folderPath);

    // 记录到数据库
    const relativePath = path.join(relativeBase, folderName.trim());
    db.run(`INSERT INTO resources (teacher_id, resource_name, resource_type, file_path, file_size, is_folder)
            VALUES (?, ?, ?, ?, ?, ?)`,
      [req.session.teacherId, folderName.trim(), 'folder', relativePath, 0, 1],
      function(err) {
        if (err) {
          console.error('记录文件夹失败:', err);
          return res.status(500).json({ success: false, message: '创建失败' });
        }
        res.json({
          success: true,
          resourceId: this.lastID,
          message: '文件夹创建成功'
        });
      }
    );
  } catch (err) {
    console.error('创建文件夹失败:', err);
    return res.status(500).json({ success: false, message: '创建文件夹失败' });
  }
});

// 获取教师的所有资源
app.get('/api/resources', (req, res) => {
  if (!req.session.teacherId) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  db.all('SELECT * FROM resources WHERE teacher_id = ? ORDER BY created_at DESC',
    [req.session.teacherId],
    (err, resources) => {
      if (err) {
        return res.status(500).json({ success: false, message: '获取资源列表失败' });
      }
      res.json({ success: true, resources });
    }
  );
});

// 浏览服务器目录（仅限当前教师的资源目录）
app.post('/api/resources/browse', (req, res) => {
  if (!req.session.teacherId) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  const { dirPath } = req.body;
  const teacherDir = path.join(resourcesDir, `teacher_${req.session.teacherId}`);

  // 确保教师目录存在
  if (!fs.existsSync(teacherDir)) {
    fs.mkdirSync(teacherDir, { recursive: true });
  }

  // 安全检查：只能访问教师自己的目录
  let browsePath;
  if (!dirPath || dirPath === '/') {
    browsePath = teacherDir;
  } else {
    browsePath = path.join(teacherDir, dirPath);
    // 确保路径在教师目录内
    if (!browsePath.startsWith(teacherDir)) {
      return res.status(403).json({ success: false, message: '无权访问此路径' });
    }
  }

  if (!fs.existsSync(browsePath)) {
    return res.status(404).json({ success: false, message: '路径不存在' });
  }

  try {
    const items = fs.readdirSync(browsePath, { withFileTypes: true });
    const result = items.map(item => {
      const itemPath = path.join(browsePath, item.name);
      const stats = fs.statSync(itemPath);
      const relativePath = path.relative(teacherDir, itemPath);

      return {
        name: item.name,
        path: relativePath.replace(/\\/g, '/'), // 统一使用正斜杠
        isDirectory: item.isDirectory(),
        size: item.isDirectory() ? 0 : stats.size,
        modifiedAt: stats.mtime
      };
    });

    res.json({ success: true, items: result, currentPath: dirPath || '/' });
  } catch (error) {
    console.error('浏览目录失败:', error);
    res.status(500).json({ success: false, message: '浏览目录失败' });
  }
});

// 重命名资源文件/文件夹
app.post('/api/resources/rename', (req, res) => {
  if (!req.session.teacherId) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  const { oldPath, newName } = req.body;

  if (!oldPath || !newName || !newName.trim()) {
    return res.json({ success: false, message: '请提供路径和新名称' });
  }

  // 安全检查：新名称不能包含路径分隔符
  if (newName.includes('/') || newName.includes('\\') || newName.includes('..')) {
    return res.json({ success: false, message: '名称不合法' });
  }

  const teacherDir = path.join(resourcesDir, `teacher_${req.session.teacherId}`);
  const oldFullPath = path.join(teacherDir, oldPath);
  const resolvedOld = path.resolve(oldFullPath);

  // 确保路径在教师目录内
  if (!resolvedOld.startsWith(path.resolve(teacherDir))) {
    return res.status(403).json({ success: false, message: '无权操作此路径' });
  }

  if (!fs.existsSync(oldFullPath)) {
    return res.json({ success: false, message: '文件不存在' });
  }

  const parentDir = path.dirname(oldFullPath);
  const newFullPath = path.join(parentDir, newName.trim());

  if (fs.existsSync(newFullPath)) {
    return res.json({ success: false, message: '同名文件已存在' });
  }

  try {
    fs.renameSync(oldFullPath, newFullPath);

    // 更新数据库中的记录
    const oldRelative = path.join(`teacher_${req.session.teacherId}`, oldPath);
    const newRelative = path.join(path.dirname(oldRelative), newName.trim());
    db.run('UPDATE resources SET resource_name = ?, file_path = ? WHERE teacher_id = ? AND file_path = ?',
      [newName.trim(), newRelative, req.session.teacherId, oldRelative],
      function(err) {
        if (err) {
          console.error('更新数据库失败:', err);
        }
      }
    );

    res.json({ success: true, message: '重命名成功' });
  } catch (error) {
    console.error('重命名失败:', error);
    res.status(500).json({ success: false, message: '重命名失败' });
  }
});

// 删除资源
app.delete('/api/resources/:resourceId', (req, res) => {
  if (!req.session.teacherId) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  const { resourceId } = req.params;

  db.get('SELECT * FROM resources WHERE id = ? AND teacher_id = ?',
    [resourceId, req.session.teacherId],
    (err, resource) => {
      if (err || !resource) {
        return res.status(404).json({ success: false, message: '资源不存在' });
      }

      // 删除文件
      const filePath = path.join(resourcesDir, resource.file_path);
      if (fs.existsSync(filePath)) {
        try {
          fs.unlinkSync(filePath);
        } catch (err) {
          console.error('删除文件失败:', err);
        }
      }

      // 删除数据库记录
      db.run('DELETE FROM resources WHERE id = ?', [resourceId], (err) => {
        if (err) {
          return res.status(500).json({ success: false, message: '删除失败' });
        }
        res.json({ success: true, message: '资源已删除' });
      });
    }
  );
});

// 按路径删除资源文件
app.post('/api/resources/delete-by-path', (req, res) => {
  if (!req.session.teacherId) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  const { filePath, forceDelete } = req.body;

  if (!filePath) {
    return res.json({ success: false, message: '请提供文件路径' });
  }

  const teacherDir = path.join(resourcesDir, `teacher_${req.session.teacherId}`);
  const fullPath = path.join(teacherDir, filePath);
  const resolvedPath = path.resolve(fullPath);

  // 安全检查：确保路径在教师目录内
  if (!resolvedPath.startsWith(path.resolve(teacherDir))) {
    return res.status(403).json({ success: false, message: '无权删除此文件' });
  }

  if (!fs.existsSync(fullPath)) {
    return res.json({ success: false, message: '文件不存在' });
  }

  // 检查是否有关联的共享
  const dbPath = path.join(`teacher_${req.session.teacherId}`, filePath);
  const pathPattern = dbPath + '%'; // 用于匹配子目录

  // 查找口令共享
  db.all(`SELECT id, share_code, share_name, share_type FROM shares
          WHERE teacher_id = ? AND (resource_data = ? OR resource_data LIKE ?)`,
    [req.session.teacherId, dbPath, pathPattern],
    (err, codeShares) => {
      if (err) {
        console.error('查询口令共享失败:', err);
        codeShares = [];
      }

      // 查找班级共享
      db.all(`SELECT cs.id, cs.share_name, cs.share_type, c.name as class_name
              FROM class_shares cs
              LEFT JOIN classes c ON cs.class_id = c.id
              WHERE cs.teacher_id = ? AND (cs.resource_path = ? OR cs.resource_path LIKE ?)`,
        [req.session.teacherId, dbPath, pathPattern],
        (err, classShares) => {
          if (err) {
            console.error('查询班级共享失败:', err);
            classShares = [];
          }

          const totalShares = (codeShares || []).length + (classShares || []).length;

          // 如果有共享且未强制删除，返回共享信息
          if (totalShares > 0 && !forceDelete) {
            return res.json({
              success: false,
              hasShares: true,
              codeShares: codeShares || [],
              classShares: classShares || [],
              message: `该资源有 ${totalShares} 个关联共享，删除后共享将失效`
            });
          }

          // 执行删除
          try {
            const stats = fs.statSync(fullPath);
            if (stats.isDirectory()) {
              fs.rmSync(fullPath, { recursive: true, force: true });
            } else {
              fs.unlinkSync(fullPath);
            }

            // 删除数据库中的资源记录
            db.run('DELETE FROM resources WHERE teacher_id = ? AND file_path = ?',
              [req.session.teacherId, dbPath]);

            // 删除关联的口令共享
            if (codeShares && codeShares.length > 0) {
              const codeShareIds = codeShares.map(s => s.id).join(',');
              db.run(`DELETE FROM shares WHERE id IN (${codeShareIds})`);
            }

            // 删除关联的班级共享
            if (classShares && classShares.length > 0) {
              const classShareIds = classShares.map(s => s.id).join(',');
              db.run(`DELETE FROM class_shares WHERE id IN (${classShareIds})`);
            }

            res.json({
              success: true,
              message: totalShares > 0 ? `已删除，同时删除了 ${totalShares} 个关联共享` : '已删除'
            });
          } catch (error) {
            console.error('删除文件失败:', error);
            res.status(500).json({ success: false, message: '删除失败: ' + error.message });
          }
        }
      );
    }
  );
});

// ==================== 共享功能 API ====================

// 生成随机共享码（6位，包含大小写字母和数字，避免易混淆字符）
function generateShareCode() {
  const chars = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789'; // 排除 0,O,1,l,I
  let code = '';
  for (let i = 0; i < 6; i++) {
    code += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return code;
}

// 创建共享
app.post('/api/shares/create', (req, res) => {
  if (!req.session.teacherId) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  const { shareType, shareName, resourceData, description, maxAccess, expireAt, customCode } = req.body;

  // shareType: 'file' | 'directory' | 'multiple' | 'assignment'
  // resourceData: 对于file/directory是路径字符串，对于multiple是路径数组的JSON，对于assignment是作业ID

  if (!shareType) {
    return res.status(400).json({ success: false, message: '请指定共享类型' });
  }

  if (!resourceData) {
    return res.status(400).json({ success: false, message: '请指定共享内容' });
  }

  // 验证资源
  if (shareType === 'assignment') {
    // 共享作业（保留原有功能）
    db.get('SELECT * FROM assignments WHERE id = ? AND teacher_id = ?',
      [resourceData, req.session.teacherId],
      (err, assignment) => {
        if (err || !assignment) {
          return res.status(403).json({ success: false, message: '无权共享此作业' });
        }

        createShareRecord(shareType, resourceData, shareName || assignment.assignment_name);
      }
    );
  } else if (shareType === 'file' || shareType === 'directory') {
    // 共享单个文件或目录
    // resourceData 可能是相对于教师目录的路径，也可能是完整路径
    let actualPath = resourceData;
    const teacherPrefix = `teacher_${req.session.teacherId}`;

    // 去除可能的前导斜杠
    if (resourceData.startsWith('/')) {
      actualPath = resourceData.substring(1);
    }

    // 如果路径不是以 teacher_X 开头，添加前缀
    if (!actualPath.startsWith(teacherPrefix) && !actualPath.startsWith('teacher_')) {
      actualPath = path.join(teacherPrefix, actualPath);
    }

    const fullPath = path.join(resourcesDir, actualPath);

    console.log('[共享调试] resourceData:', resourceData);
    console.log('[共享调试] actualPath:', actualPath);
    console.log('[共享调试] fullPath:', fullPath);
    console.log('[共享调试] 文件存在:', fs.existsSync(fullPath));

    // 安全检查
    const teacherDir = path.join(resourcesDir, teacherPrefix);
    if (!path.resolve(fullPath).startsWith(path.resolve(teacherDir))) {
      return res.status(403).json({ success: false, message: '无权共享此路径' });
    }

    if (!fs.existsSync(fullPath)) {
      return res.status(404).json({ success: false, message: '文件或目录不存在' });
    }

    const stats = fs.statSync(fullPath);
    if (shareType === 'directory' && !stats.isDirectory()) {
      return res.status(400).json({ success: false, message: '指定路径不是目录' });
    }
    if (shareType === 'file' && stats.isDirectory()) {
      return res.status(400).json({ success: false, message: '指定路径不是文件' });
    }

    createShareRecord(shareType, actualPath, shareName || path.basename(resourceData));

  } else if (shareType === 'multiple') {
    // 共享多个文件
    let files;
    try {
      files = JSON.parse(resourceData);
      if (!Array.isArray(files) || files.length === 0) {
        return res.status(400).json({ success: false, message: '请选择要共享的文件' });
      }
    } catch (err) {
      return res.status(400).json({ success: false, message: '无效的文件列表' });
    }

    const teacherPrefix = `teacher_${req.session.teacherId}`;
    const teacherDir = path.join(resourcesDir, teacherPrefix);
    const actualFiles = [];

    // 验证所有文件都存在，并添加前缀
    for (const filePath of files) {
      let actualPath = filePath;
      if (!filePath.startsWith(teacherPrefix) && !filePath.startsWith('teacher_')) {
        actualPath = path.join(teacherPrefix, filePath);
      }
      const fullPath = path.join(resourcesDir, actualPath);
      if (!path.resolve(fullPath).startsWith(path.resolve(teacherDir)) || !fs.existsSync(fullPath)) {
        return res.status(403).json({ success: false, message: `文件不存在或无权访问: ${filePath}` });
      }
      actualFiles.push(actualPath);
    }

    createShareRecord(shareType, JSON.stringify(actualFiles), shareName || `${files.length}个文件`);
  } else {
    return res.status(400).json({ success: false, message: '不支持的共享类型' });
  }

  function createShareRecord(type, data, name) {
    // 如果提供了自定义共享码，先验证
    if (customCode && customCode.trim()) {
      const code = customCode.trim();
      // 验证格式：只允许字母数字
      if (code.length < 1) {
        return res.status(400).json({ success: false, message: '共享码不能为空' });
      }
      if (!/^[a-zA-Z0-9]+$/.test(code)) {
        return res.status(400).json({ success: false, message: '共享码只能包含字母和数字' });
      }
      // 检查是否已存在
      db.get('SELECT id FROM shares WHERE share_code = ?', [code], (err, existing) => {
        if (existing) {
          return res.status(400).json({ success: false, message: '该共享码已被使用，请换一个' });
        }
        insertShare(code);
      });
    } else {
      // 随机生成
      generateUniqueShareCode((shareCode) => {
        insertShare(shareCode);
      });
    }

    function insertShare(shareCode) {
      db.run(`INSERT INTO shares (share_code, teacher_id, share_type, resource_data, share_name, description, max_access, expire_at)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
        [shareCode, req.session.teacherId, type, data, name, description || null, maxAccess || 0, expireAt || null],
        function(err) {
          if (err) {
            console.error('创建共享失败:', err);
            return res.status(500).json({ success: false, message: '创建共享失败' });
          }
          res.json({ success: true, shareCode, shareId: this.lastID });
        }
      );
    }
  }
});

// 生成唯一的共享码
function generateUniqueShareCode(callback) {
  const shareCode = generateShareCode();

  // 检查是否重复
  db.get('SELECT * FROM shares WHERE share_code = ?', [shareCode], (err, existing) => {
    if (existing) {
      // 如果重复，递归生成新的
      generateUniqueShareCode(callback);
    } else {
      callback(shareCode);
    }
  });
}

// 获取共享信息
app.get('/api/shares/:shareCode/info', (req, res) => {
  const { shareCode } = req.params;

  db.get(`SELECT s.*, t.name as teacher_name
          FROM shares s
          LEFT JOIN teachers t ON s.teacher_id = t.id
          WHERE s.share_code = ?`,
    [shareCode],
    (err, share) => {
      if (err) {
        return res.status(500).json({ success: false, message: '服务器错误' });
      }

      if (!share) {
        return res.json({ success: false, message: '共享码不存在或已失效' });
      }

      // 检查是否过期
      if (share.expire_at) {
        const now = new Date();
        const expireDate = new Date(share.expire_at);
        if (now > expireDate) {
          return res.json({ success: false, message: '共享已过期' });
        }
      }

      // 检查访问次数限制
      if (share.max_access > 0 && share.access_count >= share.max_access) {
        return res.json({ success: false, message: '已达到最大访问次数' });
      }

      // 返回共享信息（不包含敏感信息）
      res.json({
        success: true,
        share: {
          shareCode: share.share_code,
          shareType: share.share_type,
          shareName: share.share_name,
          description: share.description,
          teacherName: share.teacher_name,
          accessCount: share.access_count,
          maxAccess: share.max_access,
          expireAt: share.expire_at,
          createdAt: share.created_at
        }
      });
    }
  );
});

// 下载共享内容
app.get('/api/shares/:shareCode/download', (req, res) => {
  const { shareCode } = req.params;

  db.get(`SELECT * FROM shares WHERE share_code = ?`, [shareCode], (err, share) => {
    if (err) {
      return res.status(500).json({ success: false, message: '服务器错误' });
    }

    if (!share) {
      return res.status(404).json({ success: false, message: '共享码不存在或已失效' });
    }

    // 检查是否过期
    if (share.expire_at) {
      const now = new Date();
      const expireDate = new Date(share.expire_at);
      if (now > expireDate) {
        return res.status(403).json({ success: false, message: '共享已过期' });
      }
    }

    // 检查访问次数限制
    if (share.max_access > 0 && share.access_count >= share.max_access) {
      return res.status(403).json({ success: false, message: '已达到最大访问次数' });
    }

    // 更新访问计数
    db.run('UPDATE shares SET access_count = access_count + 1 WHERE share_code = ?', [shareCode]);

    // 根据共享类型处理下载
    if (share.share_type === 'assignment') {
      // 下载作业（保留原有功能）
      db.get('SELECT * FROM assignments WHERE id = ?', [share.resource_data], (err, assignment) => {
        if (err || !assignment) {
          return res.status(404).json({ success: false, message: '作业不存在' });
        }

        const assignmentDir = path.join(uploadsDir, `teacher_${share.teacher_id}`, `assignment_${share.resource_data}`);

        if (!fs.existsSync(assignmentDir)) {
          return res.status(404).json({ success: false, message: '作业文件不存在' });
        }

        const files = fs.readdirSync(assignmentDir);
        if (files.length === 0) {
          return res.status(404).json({ success: false, message: '作业暂无提交文件' });
        }

        // 设置响应头
        const zipFilename = `${share.share_name || 'assignment'}_${Date.now()}.zip`;
        res.setHeader('Content-Type', 'application/zip');
        res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(zipFilename)}"`);

        // 创建 zip 压缩流
        const archive = archiver('zip', { zlib: { level: 9 } });

        archive.on('error', (err) => {
          console.error('压缩失败:', err);
          res.status(500).end();
        });

        archive.pipe(res);
        archive.directory(assignmentDir, false);
        archive.finalize();
      });

    } else if (share.share_type === 'file') {
      // 下载单个文件
      const filePath = path.join(resourcesDir, share.resource_data);

      if (!fs.existsSync(filePath)) {
        return res.status(404).json({ success: false, message: '文件不存在' });
      }

      // 获取文件名
      const filename = path.basename(filePath);
      res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(filename)}"`);

      // 发送文件
      res.sendFile(filePath);

    } else if (share.share_type === 'directory') {
      // 下载整个目录（打包成ZIP）
      const dirPath = path.join(resourcesDir, share.resource_data);

      if (!fs.existsSync(dirPath)) {
        return res.status(404).json({ success: false, message: '目录不存在' });
      }

      const stats = fs.statSync(dirPath);
      if (!stats.isDirectory()) {
        return res.status(400).json({ success: false, message: '指定路径不是目录' });
      }

      // 设置响应头
      const zipFilename = `${share.share_name || path.basename(dirPath)}_${Date.now()}.zip`;
      res.setHeader('Content-Type', 'application/zip');
      res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(zipFilename)}"`);

      // 创建 zip 压缩流
      const archive = archiver('zip', { zlib: { level: 9 } });

      archive.on('error', (err) => {
        console.error('压缩失败:', err);
        res.status(500).end();
      });

      archive.pipe(res);
      archive.directory(dirPath, false);
      archive.finalize();

    } else if (share.share_type === 'multiple') {
      // 下载多个文件（打包成ZIP）
      let files;
      try {
        files = JSON.parse(share.resource_data);
      } catch (err) {
        return res.status(400).json({ success: false, message: '无效的文件列表' });
      }

      // 设置响应头
      const zipFilename = `${share.share_name || 'files'}_${Date.now()}.zip`;
      res.setHeader('Content-Type', 'application/zip');
      res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(zipFilename)}"`);

      // 创建 zip 压缩流
      const archive = archiver('zip', { zlib: { level: 9 } });

      archive.on('error', (err) => {
        console.error('压缩失败:', err);
        res.status(500).end();
      });

      archive.pipe(res);

      // 添加所有文件到ZIP
      files.forEach(filePath => {
        const fullPath = path.join(resourcesDir, filePath);
        if (fs.existsSync(fullPath)) {
          const fileName = path.basename(filePath);
          archive.file(fullPath, { name: fileName });
        }
      });

      archive.finalize();
    }
  });
});

// 获取教师的所有共享
app.get('/api/shares', (req, res) => {
  if (!req.session.teacherId) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  db.all(`SELECT * FROM shares WHERE teacher_id = ? ORDER BY created_at DESC`,
    [req.session.teacherId],
    (err, shares) => {
      if (err) {
        return res.status(500).json({ success: false, message: '获取共享列表失败' });
      }

      // 检查每个共享的状态
      const now = new Date();
      const sharesWithStatus = shares.map(share => {
        let status = 'active';

        if (share.expire_at) {
          const expireDate = new Date(share.expire_at);
          if (now > expireDate) {
            status = 'expired';
          }
        }

        if (share.max_access > 0 && share.access_count >= share.max_access) {
          status = 'limit_reached';
        }

        return { ...share, status };
      });

      res.json({ success: true, shares: sharesWithStatus });
    }
  );
});

// 获取共享目录的文件列表
app.get('/api/shares/:shareCode/files', (req, res) => {
  const { shareCode } = req.params;
  const { subPath } = req.query; // 子目录路径

  db.get(`SELECT * FROM shares WHERE share_code = ?`, [shareCode], (err, share) => {
    if (err || !share) {
      return res.status(404).json({ success: false, message: '共享不存在' });
    }

    // 检查是否过期
    if (share.expire_at) {
      const now = new Date();
      const expireDate = new Date(share.expire_at);
      if (now > expireDate) {
        return res.status(403).json({ success: false, message: '共享已过期' });
      }
    }

    // 检查访问次数限制
    if (share.max_access > 0 && share.access_count >= share.max_access) {
      return res.status(403).json({ success: false, message: '已达到最大访问次数' });
    }

    // 只有目录类型的共享才能列出文件
    if (share.share_type !== 'directory') {
      return res.status(400).json({ success: false, message: '此共享不是目录类型' });
    }

    // 构建目录路径
    let dirPath = path.join(resourcesDir, share.resource_data);
    if (subPath) {
      dirPath = path.join(dirPath, subPath);
      // 安全检查
      if (!dirPath.startsWith(path.join(resourcesDir, share.resource_data))) {
        return res.status(403).json({ success: false, message: '无权访问此路径' });
      }
    }

    if (!fs.existsSync(dirPath)) {
      return res.status(404).json({ success: false, message: '目录不存在' });
    }

    try {
      const items = fs.readdirSync(dirPath, { withFileTypes: true });
      const result = items.map(item => {
        const itemPath = path.join(dirPath, item.name);
        const stats = fs.statSync(itemPath);
        const relativePath = path.relative(path.join(resourcesDir, share.resource_data), itemPath);

        return {
          name: item.name,
          path: relativePath.replace(/\\/g, '/'),
          isDirectory: item.isDirectory(),
          size: item.isDirectory() ? 0 : stats.size,
          modifiedAt: stats.mtime
        };
      });

      res.json({
        success: true,
        files: result,
        currentPath: subPath || '/',
        shareName: share.share_name
      });
    } catch (error) {
      console.error('读取目录失败:', error);
      res.status(500).json({ success: false, message: '读取目录失败' });
    }
  });
});

// 下载共享目录中的选中文件
app.post('/api/shares/:shareCode/download-selected', (req, res) => {
  const { shareCode } = req.params;
  let { files } = req.body; // 文件路径数组

  // 如果是JSON字符串，解析它
  if (typeof files === 'string') {
    try {
      files = JSON.parse(files);
    } catch (e) {
      return res.status(400).json({ success: false, message: '文件列表格式错误' });
    }
  }

  if (!files || !Array.isArray(files) || files.length === 0) {
    return res.status(400).json({ success: false, message: '请选择要下载的文件' });
  }

  db.get(`SELECT * FROM shares WHERE share_code = ?`, [shareCode], (err, share) => {
    if (err || !share) {
      return res.status(404).json({ success: false, message: '共享不存在' });
    }

    // 检查是否过期
    if (share.expire_at) {
      const now = new Date();
      const expireDate = new Date(share.expire_at);
      if (now > expireDate) {
        return res.status(403).json({ success: false, message: '共享已过期' });
      }
    }

    // 检查访问次数限制
    if (share.max_access > 0 && share.access_count >= share.max_access) {
      return res.status(403).json({ success: false, message: '已达到最大访问次数' });
    }

    // 更新访问计数
    db.run('UPDATE shares SET access_count = access_count + 1 WHERE share_code = ?', [shareCode]);

    const baseDir = path.join(resourcesDir, share.resource_data);

    // 验证所有文件路径
    const validFiles = [];
    for (const filePath of files) {
      const fullPath = path.join(baseDir, filePath);
      // 安全检查
      if (!fullPath.startsWith(baseDir)) {
        return res.status(403).json({ success: false, message: '无权访问此文件' });
      }
      if (!fs.existsSync(fullPath)) {
        return res.status(404).json({ success: false, message: `文件不存在: ${filePath}` });
      }
      validFiles.push({ path: fullPath, name: filePath });
    }

    // 如果只有一个文件且不是目录，直接下载
    if (validFiles.length === 1) {
      const stats = fs.statSync(validFiles[0].path);
      if (!stats.isDirectory()) {
        const filename = path.basename(validFiles[0].path);
        res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(filename)}"`);
        return res.sendFile(validFiles[0].path);
      }
    }

    // 多个文件或包含目录，打包成ZIP
    const zipFilename = `${share.share_name || 'download'}_${Date.now()}.zip`;
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(zipFilename)}"`);

    const archive = archiver('zip', { zlib: { level: 9 } });

    archive.on('error', (err) => {
      console.error('压缩失败:', err);
      res.status(500).end();
    });

    archive.pipe(res);

    // 添加文件到ZIP
    validFiles.forEach(file => {
      const stats = fs.statSync(file.path);
      if (stats.isDirectory()) {
        archive.directory(file.path, file.name);
      } else {
        archive.file(file.path, { name: file.name });
      }
    });

    archive.finalize();
  });
});

// 下载共享目录中的单个文件
app.get('/api/shares/:shareCode/download-file', (req, res) => {
  const { shareCode } = req.params;
  const { filePath } = req.query;

  if (!filePath) {
    return res.status(400).json({ success: false, message: '请指定文件路径' });
  }

  db.get(`SELECT * FROM shares WHERE share_code = ?`, [shareCode], (err, share) => {
    if (err || !share) {
      return res.status(404).json({ success: false, message: '共享不存在' });
    }

    // 检查是否过期
    if (share.expire_at) {
      const now = new Date();
      const expireDate = new Date(share.expire_at);
      if (now > expireDate) {
        return res.status(403).json({ success: false, message: '共享已过期' });
      }
    }

    // 检查访问次数限制
    if (share.max_access > 0 && share.access_count >= share.max_access) {
      return res.status(403).json({ success: false, message: '已达到最大访问次数' });
    }

    const baseDir = path.join(resourcesDir, share.resource_data);
    const fullPath = path.join(baseDir, filePath);

    // 安全检查
    if (!fullPath.startsWith(baseDir)) {
      return res.status(403).json({ success: false, message: '无权访问此文件' });
    }

    if (!fs.existsSync(fullPath)) {
      return res.status(404).json({ success: false, message: '文件不存在' });
    }

    const stats = fs.statSync(fullPath);

    if (stats.isDirectory()) {
      // 如果是目录，打包成ZIP
      const zipFilename = `${path.basename(filePath)}_${Date.now()}.zip`;
      res.setHeader('Content-Type', 'application/zip');
      res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(zipFilename)}"`);

      const archive = archiver('zip', { zlib: { level: 9 } });
      archive.on('error', (err) => {
        console.error('压缩失败:', err);
        res.status(500).end();
      });
      archive.pipe(res);
      archive.directory(fullPath, false);
      archive.finalize();
    } else {
      // 更新访问计数（下载单个文件也计数）
      db.run('UPDATE shares SET access_count = access_count + 1 WHERE share_code = ?', [shareCode]);

      const filename = path.basename(fullPath);
      res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(filename)}"`);
      res.sendFile(fullPath);
    }
  });
});

// 删除共享
app.delete('/api/shares/:shareId', (req, res) => {
  if (!req.session.teacherId) {
    return res.status(401).json({ success: false, message: '请先登录' });
  }

  const { shareId } = req.params;

  // 验证共享是否属于当前教师
  db.get('SELECT * FROM shares WHERE id = ? AND teacher_id = ?',
    [shareId, req.session.teacherId],
    (err, share) => {
      if (err || !share) {
        return res.status(404).json({ success: false, message: '共享不存在或无权删除' });
      }

      // 删除共享
      db.run('DELETE FROM shares WHERE id = ?', [shareId], (err) => {
        if (err) {
          console.error('删除共享失败:', err);
          return res.status(500).json({ success: false, message: '删除失败' });
        }
        res.json({ success: true, message: '共享已删除' });
      });
    }
  );
});

// 获取本机 IP 地址
function getLocalIpAddress() {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      // 跳过内部和非 IPv4 地址
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }
  return 'localhost';
}

// 启动服务器，监听所有网络接口
app.listen(PORT, '0.0.0.0', () => {
  const localIp = getLocalIpAddress();
  console.log('='.repeat(60));
  console.log('📚 作业上传系统已启动');
  console.log('='.repeat(60));
  console.log(`本地访问: http://localhost:${PORT}`);
  console.log(`远程访问: http://${localIp}:${PORT}`);
  console.log('-'.repeat(60));
  console.log(`教师端: http://${localIp}:${PORT}/teacher.html`);
  console.log(`学生端: http://${localIp}:${PORT}/student.html`);
  console.log('='.repeat(60));
  console.log('默认教师账号: teacher / 123456');
  console.log('='.repeat(60));
});
