# 作业上传系统 - 开发文档

## 项目概述

基于 Node.js + Express + SQLite 构建的学生作业上传管理系统，支持多教师、多班级管理，具备密码验证、文件上传、资源共享、批量下载等完整功能。

### 技术栈

| 类型 | 技术 |
|------|------|
| 后端框架 | Node.js + Express |
| 数据库 | SQLite3 |
| 文件上传 | Multer |
| 压缩下载 | Archiver |
| 密码加密 | bcryptjs |
| 会话管理 | express-session |
| Excel导出 | xlsx |

---

## 目录结构

```
homeworkTrans/
├── server.js              # 主服务器文件（所有API）
├── database.js            # 数据库初始化和配置
├── package.json           # 项目配置
├── CLAUDE.md              # 开发文档（本文件）
├── README.md              # 用户文档
├── teachers_whitelist.txt # 教师注册白名单
├── homework.db            # SQLite数据库（运行时生成）
├── public/                # 前端静态文件
│   ├── index.html         # 首页（身份选择）
│   ├── teacher.html       # 教师端页面
│   ├── student.html       # 学生作业上传页面
│   ├── student-portal.html# 学生登录门户
│   ├── admin.html         # 管理员页面
│   └── share.html         # 共享资源访问页面
├── uploads/               # 作业上传目录
│   └── teacher_X/         # 教师X的作业目录
│       └── assignment_Y/  # 作业Y的提交文件
└── resources/             # 教学资源目录
    └── teacher_X/         # 教师X的资源文件
```

---

## 数据库设计

### ER 关系图

```
teachers (教师表)
    │
    ├─── 1:N ───→ classes (班级表)
    │                 │
    │                 ├─── 1:N ───→ students (学生表)
    │                 │
    │                 ├─── 1:N ───→ assignments (作业表)
    │                 │                    │
    │                 │                    └─── 1:N ───→ uploads (上传记录)
    │                 │
    │                 └─── 1:N ───→ class_shares (班级共享)
    │
    ├─── 1:N ───→ resources (教学资源)
    │
    └─── 1:N ───→ shares (口令共享)

admins (管理员表) ─ 独立
```

### 表结构

#### 1. teachers (教师表)
```sql
CREATE TABLE teachers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,      -- 登录用户名
  password TEXT NOT NULL,              -- bcrypt加密密码
  name TEXT NOT NULL,                  -- 教师姓名
  created_at DATETIME DEFAULT (datetime('now', 'localtime'))
)
```

#### 2. classes (班级表)
```sql
CREATE TABLE classes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  teacher_id INTEGER NOT NULL,         -- 所属教师
  name TEXT NOT NULL,                  -- 班级名称
  is_deleted INTEGER DEFAULT 0,        -- 软删除标记
  created_at DATETIME DEFAULT (datetime('now', 'localtime')),
  FOREIGN KEY (teacher_id) REFERENCES teachers(id)
)
```

#### 3. students (学生表)
```sql
CREATE TABLE students (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  class_id INTEGER NOT NULL,           -- 所属班级
  student_id TEXT NOT NULL,            -- 学号
  name TEXT NOT NULL,                  -- 姓名
  password TEXT,                       -- 登录密码（bcrypt加密）
  created_at DATETIME DEFAULT (datetime('now', 'localtime')),
  FOREIGN KEY (class_id) REFERENCES classes(id),
  UNIQUE(class_id, student_id)
)
```

#### 4. assignments (作业表)
```sql
CREATE TABLE assignments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  teacher_id INTEGER NOT NULL,         -- 所属教师
  class_id INTEGER,                    -- 所属班级（临时作业为null）
  password TEXT NOT NULL,              -- 上传密码
  deadline DATETIME NOT NULL,          -- 截止时间
  assignment_name TEXT NOT NULL,       -- 作业名称
  description TEXT,                    -- 作业描述
  is_temp INTEGER DEFAULT 0,           -- 是否临时作业
  created_at DATETIME DEFAULT (datetime('now', 'localtime')),
  FOREIGN KEY (teacher_id) REFERENCES teachers(id),
  FOREIGN KEY (class_id) REFERENCES classes(id)
)
```

#### 5. uploads (上传记录表)
```sql
CREATE TABLE uploads (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  assignment_id INTEGER NOT NULL,
  student_id TEXT NOT NULL,            -- 学号
  filename TEXT NOT NULL,              -- 保存的文件名
  original_filename TEXT,              -- 原始文件名
  upload_time DATETIME DEFAULT (datetime('now', 'localtime')),
  ip_address TEXT,                     -- 上传IP
  FOREIGN KEY (assignment_id) REFERENCES assignments(id)
)
```

#### 6. admins (管理员表)
```sql
CREATE TABLE admins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password TEXT NOT NULL,
  name TEXT NOT NULL,
  created_at DATETIME DEFAULT (datetime('now', 'localtime'))
)
```

#### 7. resources (教学资源表)
```sql
CREATE TABLE resources (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  teacher_id INTEGER NOT NULL,
  resource_name TEXT NOT NULL,
  resource_type TEXT NOT NULL,         -- 'file' | 'folder'
  file_path TEXT NOT NULL,             -- 相对路径
  file_size INTEGER DEFAULT 0,
  is_folder INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT (datetime('now', 'localtime')),
  FOREIGN KEY (teacher_id) REFERENCES teachers(id)
)
```

#### 8. shares (口令共享表)
```sql
CREATE TABLE shares (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  share_code TEXT UNIQUE NOT NULL,     -- 共享码
  teacher_id INTEGER NOT NULL,
  share_type TEXT NOT NULL,            -- 'file'|'directory'|'multiple'|'assignment'
  resource_data TEXT,                  -- 资源路径或JSON
  share_name TEXT,
  description TEXT,
  access_count INTEGER DEFAULT 0,      -- 访问次数
  max_access INTEGER DEFAULT 0,        -- 最大访问次数（0=不限）
  expire_at DATETIME,                  -- 过期时间
  created_at DATETIME DEFAULT (datetime('now', 'localtime')),
  FOREIGN KEY (teacher_id) REFERENCES teachers(id)
)
```

#### 9. class_shares (班级共享表)
```sql
CREATE TABLE class_shares (
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
)
```

---

## API 接口文档

### 认证相关

#### 教师认证

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/teacher/login` | 教师登录 |
| POST | `/api/teacher/register` | 教师注册（需白名单） |
| POST | `/api/teacher/logout` | 教师登出 |
| GET | `/api/teacher/check` | 检查登录状态 |
| POST | `/api/teacher/change-password` | 修改密码 |

#### 管理员认证

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/admin/login` | 管理员登录 |
| POST | `/api/admin/logout` | 管理员登出 |
| GET | `/api/admin/check` | 检查登录状态 |

#### 学生认证

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/student/login` | 学生登录 |
| POST | `/api/student/logout` | 学生登出 |
| GET | `/api/student/check-login` | 检查登录状态 |
| POST | `/api/student/change-password` | 修改密码 |

---

### 班级管理

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/classes` | 创建班级 |
| GET | `/api/classes` | 获取班级列表 |
| DELETE | `/api/classes/:classId` | 软删除班级 |
| GET | `/api/classes/:classId/export` | 导出作业提交Excel |

---

### 学生管理

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/classes/:classId/students/batch` | 批量添加学生 |
| GET | `/api/classes/:classId/students` | 获取学生列表 |
| DELETE | `/api/students/:studentId` | 删除单个学生 |
| POST | `/api/students/batch-delete` | 批量删除学生 |
| POST | `/api/students/:studentId/reset-password` | 重置学生密码 |

**批量添加格式：**
```
学号 姓名 [密码]
20240101 张三
20240102 李四 mypassword
```

---

### 作业管理

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/assignments` | 创建班级作业 |
| POST | `/api/assignments/temp` | 创建临时作业 |
| GET | `/api/assignments/temp` | 获取临时作业列表 |
| GET | `/api/classes/:classId/assignments` | 获取班级作业列表 |
| PUT | `/api/assignments/:assignmentId` | 编辑作业 |
| DELETE | `/api/assignments/:assignmentId` | 删除作业 |
| PUT | `/api/assignments/:assignmentId/link-class` | 关联临时作业到班级 |
| GET | `/api/assignments/:assignmentId/submissions` | 查看提交情况 |
| GET | `/api/assignments/:assignmentId/download` | 批量下载作业 |

---

### 学生作业上传

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/student/verify` | 验证上传密码 |
| POST | `/api/student/verify-student-id` | 验证学号 |
| POST | `/api/student/check-file` | 检查文件是否存在 |
| POST | `/api/student/upload` | 上传作业文件 |

**学生登录后上传：**

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/student/assignments` | 获取作业列表 |
| POST | `/api/student/upload-assignment` | 上传作业 |
| GET | `/api/student/my-uploads` | 获取上传记录 |
| GET | `/api/student/download-my-upload/:uploadId` | 下载已上传文件 |
| GET | `/api/student/class-shares` | 获取班级共享资源 |
| GET | `/api/student/download-class-share/:shareId` | 下载共享资源 |

---

### 教学资源管理

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/resources/upload` | 上传资源文件 |
| POST | `/api/resources/folder` | 创建文件夹 |
| GET | `/api/resources` | 获取资源列表 |
| POST | `/api/resources/browse` | 浏览目录 |
| POST | `/api/resources/rename` | 重命名文件/文件夹 |
| DELETE | `/api/resources/:resourceId` | 删除资源（按ID） |
| POST | `/api/resources/delete-by-path` | 删除资源（按路径） |

---

### 共享功能

#### 口令共享

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/shares/create` | 创建共享 |
| GET | `/api/shares` | 获取共享列表 |
| DELETE | `/api/shares/:shareId` | 删除共享 |
| GET | `/api/shares/:shareCode/info` | 获取共享信息 |
| GET | `/api/shares/:shareCode/download` | 下载共享内容 |
| GET | `/api/shares/:shareCode/files` | 获取目录文件列表 |
| POST | `/api/shares/:shareCode/download-selected` | 下载选中文件 |
| GET | `/api/shares/:shareCode/download-file` | 下载单个文件 |

**共享类型：**
- `file` - 单个文件
- `directory` - 整个目录
- `multiple` - 多个文件
- `assignment` - 作业

#### 班级共享

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/class-shares` | 创建班级共享 |
| GET | `/api/classes/:classId/shares` | 获取班级共享列表 |
| DELETE | `/api/class-shares/:shareId` | 删除班级共享 |

---

### 管理员功能

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/admin/teachers` | 获取所有教师及班级 |
| GET | `/api/admin/stats` | 获取系统统计 |
| POST | `/api/admin/reset-teacher-password` | 重置教师密码 |
| DELETE | `/api/admin/classes/:classId` | 硬删除班级 |

---

## 前端页面

### 1. 教师端 (`teacher.html`)

**四大功能模块：**

1. **班级管理** - 创建班级、管理学生
2. **作业管理** - 班级作业 + 临时作业统一管理
3. **教学资源** - 文件浏览器界面，上传/创建文件夹/共享
4. **资源共享** - 口令共享 + 班级共享汇总

### 2. 学生端

- `student.html` - 密码验证上传（无需登录）
- `student-portal.html` - 学生登录门户（查看作业、历史）

### 3. 管理员端 (`admin.html`)

- 查看所有教师和班级
- 重置教师密码
- 硬删除班级

### 4. 共享页面 (`share.html`)

- 输入共享码访问资源
- 支持单文件下载、目录浏览、批量下载

---

## 文件存储结构

### 作业文件
```
uploads/
└── teacher_1/
    ├── assignment_1/
    │   ├── 20240101_张三.zip
    │   ├── 20240102_李四.pdf
    │   └── ...
    └── assignment_2/
        └── ...
```

**命名规则：**
- 普通作业：`学号_姓名.扩展名`
- 临时作业：`学号.扩展名`

### 教学资源
```
resources/
└── teacher_1/
    ├── 课件/
    │   ├── 第一章.ppt
    │   └── 第二章.ppt
    ├── 资料.pdf
    └── ...
```

---

## 核心功能说明

### 1. 作业密码验证

```javascript
// 密码验证流程
1. 学生输入密码
2. 查询有效作业（未过期）
3. 验证成功 → 保存到Session
4. 普通作业需验证学号，临时作业跳过
```

### 2. 文件上传处理

```javascript
// 上传流程
1. 接收文件到临时目录
2. 查询学生姓名
3. 重命名为"学号_姓名.扩展名"
4. 移动到作业目录
5. 删除旧文件（覆盖上传）
6. 记录到uploads表
```

### 3. 共享码生成

```javascript
// 共享码规则
- 随机生成6位
- 包含大小写字母和数字
- 排除易混淆字符(0,O,1,l,I)
- 支持自定义共享码
```

### 4. 班级软删除

```javascript
// 软删除机制
教师删除 → is_deleted = 1
管理员可见已删除班级
管理员硬删除 → 删除所有关联数据和文件
```

---

## 安全机制

### 1. 密码安全
- bcrypt 10轮加密
- Session 24小时过期

### 2. 路径安全
```javascript
// 所有文件操作都验证路径
if (!resolvedPath.startsWith(teacherDir)) {
  return res.status(403).json({ message: '无权访问' });
}
```

### 3. 权限验证
- 教师只能操作自己的班级/资源
- 学生只能访问自己班级的共享
- 管理员可操作所有数据

### 4. SQL注入防护
- 使用参数化查询
- 不拼接SQL语句

---

## 部署指南

### 开发环境

```bash
# 安装依赖
npm install

# 开发模式（热重载）
npm run dev

# 生产模式
npm start
```

### 默认账号

| 角色 | 用户名 | 密码 |
|------|--------|------|
| 教师 | teacher | 123456 |
| 管理员 | admin | admin123 |
| 学生 | 学号 | 123456 |

### 端口配置

```javascript
// server.js 第13行
const PORT = 8080;  // 修改此处
```

### 生产环境

```bash
# 使用PM2
pm2 start server.js --name homework-system
pm2 startup
pm2 save
```

---

## 依赖版本

```json
{
  "express": "^4.18.2",
  "express-session": "^1.17.3",
  "multer": "^1.4.5-lts.1",
  "sqlite3": "^5.1.6",
  "bcryptjs": "^2.4.3",
  "archiver": "^7.0.1",
  "xlsx": "^0.18.5"
}
```

---

## 常见问题

### Q: 如何重置数据库？
删除 `homework.db` 文件，重启服务器自动创建。

### Q: 上传文件存储在哪里？
`uploads/teacher_X/assignment_Y/`

### Q: 教学资源存储在哪里？
`resources/teacher_X/`

### Q: 如何添加教师到白名单？
编辑 `teachers_whitelist.txt`，每行一个姓名。

### Q: 如何备份数据？
备份以下文件：
- `homework.db`
- `uploads/` 目录
- `resources/` 目录
- `teachers_whitelist.txt`

---

## 版本历史

**v1.4.0** (2025年2月)
- 页面结构重构（四大模块）
- 文件浏览器界面
- 资源共享增强
- 自定义共享码

**v1.3.0** (2025年1月)
- 作业编辑功能
- 班级软删除
- 时间本地化

**v1.2.0** (2025年1月)
- 临时作业功能
- 作业描述字段
- 密码冲突检测

**v1.1.0** (2025年1月)
- 管理员系统
- 教师白名单
- 批量下载优化

**v1.0.0** (2025年1月)
- 基础功能实现
