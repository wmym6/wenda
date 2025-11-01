const sql = require("mssql");
const express = require("express");
const bcrypt = require("bcrypt");
const cors = require("cors");
const path = require("path");

const app = express();
const port = 3000;

// ======================
// 1. 中间件配置
// ======================
app.use(
  cors({
    origin: ["http://localhost:3000"],
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type"],
    credentials: true,
  })
);
app.use(express.json());

const staticFilePath = path.join(__dirname, "../public");
console.log("✅ 静态文件目录已配置:", staticFilePath);

// ======================
// 2. 数据库配置
// ======================
const dbConfig = {
  server: "localhost",
  database: "在线问答系统",
  user: "sa",
  password: "123",
  options: {
    encrypt: false,
    port: 1433,
    trustServerCertificate: true,
    connectTimeout: 30000,
  },
};

let dbPool = null;
async function getDbConnection() {
  if (dbPool) return dbPool;
  try {
    dbPool = await sql.connect(dbConfig);
    console.log("✅ 数据库连接成功");
    return dbPool;
  } catch (err) {
    console.error("❌ 数据库连接失败:", err.message);
    dbPool = null;
    return null;
  }
}

function formatBeijingTime(dateValue) {
  if (!dateValue) return "";
  // 1. 接收Node.js解析后的时间（误将数据库北京时间当作UTC时间）
  const date = new Date(dateValue);
  // 2. 强制减去8小时，恢复为数据库原始北京时间
  date.setHours(date.getHours() - 8);

  // 3. 格式化显示格式：YYYY-MM-DD HH:MM:SS
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  const hour = String(date.getHours()).padStart(2, "0");
  const minute = String(date.getMinutes()).padStart(2, "0");
  const second = String(date.getSeconds()).padStart(2, "0");

  return `${year}-${month}-${day} ${hour}:${minute}:${second}`;
}

// ======================
// 3. API接口定义（所有返回时间均用修复后的函数处理）
// ======================
app.get("/api/test", (req, res) => {
  // 模拟数据库存储的北京时间（如当前实际时间18:30）
  const mockDbTime = new Date();
  mockDbTime.setHours(18, 30, 0); // 模拟数据库存储的北京时间18:30

  res.json({
    status: "success",
    message: "服务器运行正常",
    staticPath: staticFilePath,
    availableAPIs: ["POST /api/register", "POST /api/login"],
    // 测试：显示修复前后对比
    mockDbTime: mockDbTime.toLocaleString(), // 模拟数据库存储的北京时间
    parsedByNode: new Date(mockDbTime).toLocaleString(), // Node.js错误解析后的时间（快8小时）
    fixedBeijingTime: formatBeijingTime(mockDbTime), // 修复后显示的正确时间
  });
});

app.post("/api/register", async (req, res) => {
  try {
    const pool = await getDbConnection();
    if (!pool) {
      return res.status(500).json({ message: "数据库连接失败，请稍后重试" });
    }

    const { username, password, role } = req.body;
    if (!username || username.trim() === "")
      return res.status(400).json({ message: "用户名不能为空" });
    if (!password || password.length < 6)
      return res.status(400).json({ message: "密码长度不能少于6位" });
    if (!["user", "admin"].includes(role))
      return res.status(400).json({ message: "角色必须是普通用户或管理员" });

    const userCheck = await pool
      .request()
      .input("username", sql.VarChar(50), username)
      .query("SELECT username FROM users WHERE username = @username");
    if (userCheck.recordset.length > 0)
      return res.status(400).json({ message: "用户名已存在" });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // 存储时间：直接用数据库GETDATE()（北京时间）
    const result = await pool
      .request()
      .input("username", sql.VarChar(50), username)
      .input("password", sql.VarChar(255), hashedPassword)
      .input("role", sql.VarChar(10), role)
      .query(
        `INSERT INTO users (username, password, role, created_at) VALUES (@username, @password, @role, GETDATE())`
      );

    if (result.rowsAffected[0] > 0) {
      res.status(200).json({ message: "注册成功，请登录" });
    } else {
      res.status(500).json({ message: "注册失败，数据库写入错误" });
    }
  } catch (err) {
    console.error("注册接口错误:", err);
    res.status(500).json({ message: `服务器错误: ${err.message}` });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const pool = await getDbConnection();
    if (!pool) {
      return res.status(500).json({ message: "数据库连接失败，请稍后重试" });
    }

    const { username, password, role } = req.body;
    if (!username || !password || !role)
      return res.status(400).json({ message: "请填写完整登录信息" });

    const userResult = await pool
      .request()
      .input("username", sql.VarChar(50), username)
      .query("SELECT * FROM users WHERE username = @username");
    if (userResult.recordset.length === 0)
      return res.status(400).json({ message: "用户名或密码错误" });

    const user = userResult.recordset[0];
    if (user.role !== role)
      return res.status(400).json({ message: "用户角色不匹配" });
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid)
      return res.status(400).json({ message: "用户名或密码错误" });

    // 时间处理：减去8小时后返回
    const { password: _, ...userData } = user;
    res.status(200).json({
      message: "登录成功，正在跳转主页",
      user: {
        ...userData,
        created_at: formatBeijingTime(userData.created_at),
      },
    });
  } catch (err) {
    console.error("登录接口错误:", err);
    res.status(500).json({ message: `服务器错误: ${err.message}` });
  }
});

// 帖子列表接口（时间减去8小时）
app.get("/api/posts", async (req, res) => {
  try {
    const pool = await getDbConnection();
    if (!pool) {
      return res.status(500).json({ message: "数据库连接失败" });
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const offset = (page - 1) * limit;

    if (page < 1) return res.status(400).json({ message: "页码不能小于1" });
    if (limit < 1 || limit > 20)
      return res.status(400).json({ message: "每页条数需在1-20之间" });

    const postsQuery = await pool.request().query(`
      SELECT p.post_id, p.title, p.content, p.author_id, p.created_at, u.username AS author_name 
      FROM posts p LEFT JOIN users u ON p.author_id = u.user_id 
      ORDER BY p.created_at DESC OFFSET ${offset} ROWS FETCH NEXT ${limit} ROWS ONLY
    `);

    const countQuery = await pool
      .request()
      .query("SELECT COUNT(*) AS total FROM posts");
    const totalPosts = countQuery.recordset[0].total;
    const posts = postsQuery.recordset.map((post) => ({
      post_id: post.post_id,
      title: post.title,
      content: post.content,
      author: {
        user_id: post.author_id,
        username: post.author_name || "匿名用户",
      },
      // 时间处理：减去8小时
      created_at: formatBeijingTime(post.created_at),
    }));

    res.status(200).json({
      success: true,
      data: {
        posts: posts,
        pagination: {
          currentPage: page,
          pageSize: limit,
          totalPages: Math.ceil(totalPosts / limit),
          totalPosts: totalPosts,
        },
      },
    });
  } catch (err) {
    console.error("获取帖子列表错误:", err);
    if (err.message.includes("Invalid object name 'posts'")) {
      return res
        .status(500)
        .json({ message: "数据库中不存在posts表，请先创建帖子表" });
    }
    res.status(500).json({ message: `服务器错误：${err.message}` });
  }
});

// 获取帖子详情（时间减去8小时）
app.get("/api/posts/:postId", async (req, res) => {
  try {
    const pool = await getDbConnection();
    if (!pool) {
      return res.status(500).json({ message: "数据库连接失败" });
    }

    const postId = req.params.postId;
    const postQuery = await pool.request().input("postId", sql.Int, postId)
      .query(`
      SELECT p.post_id, p.title, p.content, p.author_id, p.created_at, u.username AS author_name 
      FROM posts p LEFT JOIN users u ON p.author_id = u.user_id 
      WHERE p.post_id = @postId
    `);

    if (postQuery.recordset.length === 0)
      return res.status(404).json({ message: "帖子不存在" });

    const post = postQuery.recordset[0];
    res.status(200).json({
      success: true,
      data: {
        post: {
          post_id: post.post_id,
          title: post.title,
          content: post.content,
          author: {
            user_id: post.author_id,
            username: post.author_name || "匿名用户",
          },
          // 时间处理：减去8小时
          created_at: formatBeijingTime(post.created_at),
        },
      },
    });
  } catch (err) {
    console.error("获取帖子详情错误:", err);
    res.status(500).json({ message: "服务器错误" });
  }
});

// 获取评论列表（时间减去8小时）
app.get("/api/comments", async (req, res) => {
  try {
    const pool = await getDbConnection();
    if (!pool) {
      return res.status(500).json({ message: "数据库连接失败" });
    }

    const postId = req.query.postId;
    const commentQuery = await pool.request().input("postId", sql.Int, postId)
      .query(`
      SELECT c.comment_id, c.content, c.post_id, c.author_id, c.created_at, u.username AS author_name 
      FROM comments c LEFT JOIN users u ON c.author_id = u.user_id 
      WHERE c.post_id = @postId ORDER BY c.created_at DESC
    `);

    const comments = commentQuery.recordset.map((comment) => ({
      comment_id: comment.comment_id,
      content: comment.content,
      post_id: comment.post_id,
      author: {
        user_id: comment.author_id,
        username: comment.author_name || "匿名用户",
      },
      // 时间处理：减去8小时
      created_at: formatBeijingTime(comment.created_at),
    }));

    res.status(200).json({ success: true, data: { comments: comments } });
  } catch (err) {
    console.error("获取评论列表错误:", err);
    res.status(500).json({ message: "服务器错误" });
  }
});

// 发布评论（存储时间不变）
app.post("/api/comments", async (req, res) => {
  try {
    const pool = await getDbConnection();
    if (!pool) {
      return res.status(500).json({ message: "数据库连接失败" });
    }

    const { post_id, content, author_id } = req.body;
    if (!post_id || !content || !author_id)
      return res.status(400).json({ message: "参数不全" });

    const result = await pool
      .request()
      .input("post_id", sql.Int, post_id)
      .input("content", sql.Text, content)
      .input("author_id", sql.Int, author_id)
      .query(
        `INSERT INTO comments (content, post_id, author_id, created_at) VALUES (@content, @post_id, @author_id, GETDATE())`
      );

    if (result.rowsAffected[0] > 0) {
      res.status(200).json({ success: true, message: "评论发布成功" });
    } else {
      res.status(500).json({ message: "评论发布失败" });
    }
  } catch (err) {
    console.error("发布评论错误:", err);
    res.status(500).json({ message: "服务器错误" });
  }
});

// 发布帖子（存储时间不变）
app.post("/api/posts", async (req, res) => {
  try {
    const pool = await getDbConnection();
    if (!pool) {
      return res
        .status(500)
        .json({ success: false, message: "数据库连接失败" });
    }

    const { title, content, author_id } = req.body;
    if (!title || !content || !author_id)
      return res
        .status(400)
        .json({ success: false, message: "标题、内容和作者ID不能为空" });

    const userCheck = await pool
      .request()
      .input("author_id", sql.Int, author_id)
      .query("SELECT user_id FROM users WHERE user_id = @author_id");
    if (userCheck.recordset.length === 0)
      return res
        .status(403)
        .json({ success: false, message: "当前用户不存在，无法发布问题" });

    const result = await pool
      .request()
      .input("title", sql.VarChar(200), title)
      .input("content", sql.Text, content)
      .input("author_id", sql.Int, author_id)
      .query(
        `INSERT INTO posts (title, content, author_id, created_at) VALUES (@title, @content, @author_id, GETDATE())`
      );

    if (result.rowsAffected[0] > 0) {
      res.status(200).json({ success: true, message: "问题发布成功" });
    } else {
      res
        .status(500)
        .json({ success: false, message: "发布失败，数据库写入错误" });
    }
  } catch (err) {
    console.error("发布问题错误:", err);
    res
      .status(500)
      .json({ success: false, message: `服务器错误：${err.message}` });
  }
});

// ======================
// 新增：获取当前用户角色（用于前端权限判断）
// GET /api/user/role
// 请求头需携带user_id（从前端localStorage获取）
// ======================
app.get("/api/user/role", async (req, res) => {
  try {
    const pool = await getDbConnection();
    if (!pool) {
      return res
        .status(500)
        .json({ success: false, message: "数据库连接失败" });
    }

    const userId = req.query.user_id;
    if (!userId) {
      return res
        .status(400)
        .json({ success: false, message: "用户ID不能为空" });
    }

    const result = await pool
      .request()
      .input("user_id", sql.Int, userId)
      .query("SELECT role FROM users WHERE user_id = @user_id");

    if (result.recordset.length === 0) {
      return res.status(404).json({ success: false, message: "用户不存在" });
    }

    res.status(200).json({
      success: true,
      data: {
        role: result.recordset[0].role, // 返回用户角色（user/admin）
      },
    });
  } catch (err) {
    console.error("获取用户角色错误:", err);
    res.status(500).json({ success: false, message: "服务器错误" });
  }
});

// ======================
// 最终版：删除帖子接口（防止服务器崩溃）
// ======================
app.delete("/api/posts/:postId", async (req, res) => {
  let pool = null;
  try {
    // 1. 获取数据库连接（使用连接池，不手动关闭连接）
    pool = await getDbConnection();
    if (!pool) {
      return res.status(500).json({
        success: false,
        message: "数据库连接失败",
      });
    }

    const postId = req.params.postId;
    const { operator_id } = req.body;

    // 2. 参数验证
    if (!postId || !operator_id) {
      return res.status(400).json({
        success: false,
        message: "缺少参数：帖子ID或操作人ID",
      });
    }

    // 3. 权限验证
    const [postResult, userResult] = await Promise.all([
      pool
        .request()
        .input("postId", sql.Int, postId)
        .query("SELECT author_id FROM posts WHERE post_id = @postId"),

      pool
        .request()
        .input("userId", sql.Int, operator_id)
        .query("SELECT role FROM users WHERE user_id = @userId"),
    ]);

    if (postResult.recordset.length === 0) {
      return res.status(404).json({
        success: false,
        message: "帖子不存在",
      });
    }

    const postAuthorId = postResult.recordset[0].author_id;
    const userRole = userResult.recordset[0]?.role;

    if (userRole !== "admin" && operator_id != postAuthorId) {
      return res.status(403).json({
        success: false,
        message: "无权限删除此帖子",
      });
    }

    // 4. 执行单条SQL事务（数据库端原子操作）
    await pool.request().input("postId", sql.Int, postId).query(`
        BEGIN TRANSACTION;
        DELETE FROM comments WHERE post_id = @postId;
        DELETE FROM posts WHERE post_id = @postId;
        IF @@ROWCOUNT > 0
          COMMIT TRANSACTION;
        ELSE
          ROLLBACK TRANSACTION;
      `);

    // 5. 验证删除结果
    const checkPost = await pool
      .request()
      .input("postId", sql.Int, postId)
      .query("SELECT post_id FROM posts WHERE post_id = @postId");

    if (checkPost.recordset.length === 0) {
      res.status(200).json({
        success: true,
        message: "帖子及关联评论已成功删除",
      });
    } else {
      res.status(500).json({
        success: false,
        message: "删除失败：未找到可删除的帖子",
      });
    }
  } catch (err) {
    console.error("删除帖子错误:", err);
    // 确保错误响应正常返回，不阻断进程
    if (!res.headersSent) {
      res.status(500).json({
        success: false,
        message: "删除失败：" + err.message,
      });
    }
  } finally {
    // 关键修复：不手动关闭连接池，由连接池自身管理
    // （删除原有的 pool.close() 调用，避免触发未知错误）
    console.log("删除操作处理完毕，连接由池自动管理");
  }
});

// ======================
// 全局异常捕获（防止服务器崩溃）
// ======================
process.on("uncaughtException", (err) => {
  console.error("未捕获的异常导致服务器险些崩溃:", err);
  // 记录错误日志后不退出进程
});

process.on("unhandledRejection", (reason, promise) => {
  console.error("未处理的Promise拒绝:", reason, "Promise:", promise);
  // 记录错误日志后不退出进程
});

// ======================
// 新增：删除评论接口
// DELETE /api/comments/:commentId
// 请求体：{ operator_id: 当前操作用户ID }
// ======================
app.delete("/api/comments/:commentId", async (req, res) => {
  try {
    const pool = await getDbConnection();
    if (!pool) {
      return res
        .status(500)
        .json({ success: false, message: "数据库连接失败" });
    }

    const commentId = req.params.commentId;
    const { operator_id } = req.body;

    if (!commentId || !operator_id) {
      return res
        .status(400)
        .json({ success: false, message: "参数不全（评论ID/操作人ID）" });
    }

    // 1. 查询评论发布者和操作人角色
    const [commentResult, operatorResult] = await Promise.all([
      pool.request().input("commentId", sql.Int, commentId).query(`
        SELECT author_id FROM comments WHERE comment_id = @commentId
      `),
      pool.request().input("operator_id", sql.Int, operator_id).query(`
        SELECT role FROM users WHERE user_id = @operator_id
      `),
    ]);

    // 2. 验证评论是否存在
    if (commentResult.recordset.length === 0) {
      return res.status(404).json({ success: false, message: "评论不存在" });
    }

    // 3. 权限判断：管理员可删除所有，普通用户仅可删除自己的评论
    const commentAuthorId = commentResult.recordset[0].author_id;
    const operatorRole = operatorResult.recordset[0].role;
    if (operatorRole !== "admin" && operator_id != commentAuthorId) {
      return res
        .status(403)
        .json({ success: false, message: "无权限删除该评论" });
    }

    // 4. 删除评论
    const result = await pool.request().input("commentId", sql.Int, commentId)
      .query(`
      DELETE FROM comments WHERE comment_id = @commentId
    `);

    if (result.rowsAffected[0] > 0) {
      res.status(200).json({ success: true, message: "评论删除成功" });
    } else {
      res.status(500).json({ success: false, message: "评论删除失败" });
    }
  } catch (err) {
    console.error("删除评论错误:", err);
    res
      .status(500)
      .json({ success: false, message: "服务器错误：" + err.message });
  }
});

// ======================
// 修改：帖子列表接口（新增返回帖子author_id，用于前端权限判断）
// ======================
app.get("/api/posts", async (req, res) => {
  try {
    const pool = await getDbConnection();
    if (!pool) {
      return res.status(500).json({ message: "数据库连接失败" });
    }

    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 5;
    const offset = (page - 1) * limit;

    if (page < 1) return res.status(400).json({ message: "页码不能小于1" });
    if (limit < 1 || limit > 20)
      return res.status(400).json({ message: "每页条数需在1-20之间" });

    const postsQuery = await pool.request().query(`
      SELECT 
        p.post_id, 
        p.title, 
        p.content, 
        p.author_id, -- 保留author_id，用于前端判断删除权限
        p.created_at, 
        u.username AS author_name 
      FROM posts p
      LEFT JOIN users u ON p.author_id = u.user_id 
      ORDER BY p.created_at DESC 
      OFFSET ${offset} ROWS 
      FETCH NEXT ${limit} ROWS ONLY
    `);

    const countQuery = await pool
      .request()
      .query("SELECT COUNT(*) AS total FROM posts");

    const totalPosts = countQuery.recordset[0].total;
    const posts = postsQuery.recordset.map((post) => ({
      post_id: post.post_id,
      title: post.title,
      content: post.content,
      author: {
        user_id: post.author_id, // 传递发布者ID
        username: post.author_name || "匿名用户",
      },
      created_at: formatBeijingTime(post.created_at),
    }));

    res.status(200).json({
      success: true,
      data: {
        posts: posts,
        pagination: {
          currentPage: page,
          pageSize: limit,
          totalPages: Math.ceil(totalPosts / limit),
          totalPosts: totalPosts,
        },
      },
    });
  } catch (err) {
    console.error("获取帖子列表错误:", err);
    if (err.message.includes("Invalid object name 'posts'")) {
      return res
        .status(500)
        .json({ message: "数据库中不存在posts表，请先创建帖子表" });
    }
    res.status(500).json({ message: `服务器错误：${err.message}` });
  }
});

// ======================
// 修改：评论列表接口（新增返回评论author_id，用于前端权限判断）
// ======================
app.get("/api/comments", async (req, res) => {
  try {
    const pool = await getDbConnection();
    if (!pool) {
      return res.status(500).json({ message: "数据库连接失败" });
    }

    const postId = req.query.postId;
    const commentQuery = await pool.request().input("postId", sql.Int, postId)
      .query(`
        SELECT 
          c.comment_id, 
          c.content, 
          c.post_id, 
          c.author_id, -- 保留author_id
          c.created_at, 
          u.username AS author_name 
        FROM comments c
        LEFT JOIN users u ON c.author_id = u.user_id 
        WHERE c.post_id = @postId
        ORDER BY c.created_at DESC
      `);

    const comments = commentQuery.recordset.map((comment) => ({
      comment_id: comment.comment_id,
      content: comment.content,
      post_id: comment.post_id,
      author: {
        user_id: comment.author_id, // 传递评论发布者ID
        username: comment.author_name || "匿名用户",
      },
      created_at: formatBeijingTime(comment.created_at),
    }));

    res.status(200).json({
      success: true,
      data: {
        comments: comments,
      },
    });
  } catch (err) {
    console.error("获取评论列表错误:", err);
    res.status(500).json({ message: "服务器错误" });
  }
});
// ======================
// 个人中心：获取当前用户的帖子
// GET /api/user/posts
// 请求头需携带 X-User-Id: 当前用户ID
// ======================
app.get("/api/user/posts", async (req, res) => {
  try {
    const pool = await getDbConnection();
    if (!pool) {
      return res
        .status(500)
        .json({ success: false, message: "数据库连接失败" });
    }

    const userId = req.headers["x-user-id"];
    if (!userId) {
      return res.status(401).json({ success: false, message: "请先登录" });
    }

    const result = await pool.request().input("authorId", sql.Int, userId)
      .query(`
        SELECT 
          post_id, 
          title, 
          content, 
          created_at 
        FROM posts 
        WHERE author_id = @authorId
        ORDER BY created_at DESC
      `);

    // 时间格式化：统一使用修复后的北京时间
    const posts = result.recordset.map((post) => ({
      ...post,
      created_at: formatBeijingTime(post.created_at),
    }));

    res.status(200).json({
      success: true,
      data: { posts },
    });
  } catch (err) {
    console.error("获取用户帖子错误:", err);
    res
      .status(500)
      .json({ success: false, message: "服务器错误：" + err.message });
  }
});

// ======================
// 个人中心：获取当前用户的评论
// GET /api/user/comments
// 请求头需携带 X-User-Id: 当前用户ID
// ======================
app.get("/api/user/comments", async (req, res) => {
  try {
    const pool = await getDbConnection();
    if (!pool) {
      return res
        .status(500)
        .json({ success: false, message: "数据库连接失败" });
    }

    const userId = req.headers["x-user-id"];
    if (!userId) {
      return res.status(401).json({ success: false, message: "请先登录" });
    }

    const result = await pool.request().input("authorId", sql.Int, userId)
      .query(`
        SELECT 
          c.comment_id, 
          c.content, 
          c.post_id, 
          c.created_at,
          p.title AS post_title
        FROM comments c
        LEFT JOIN posts p ON c.post_id = p.post_id
        WHERE c.author_id = @authorId
        ORDER BY c.created_at DESC
      `);

    // 时间格式化：统一使用修复后的北京时间
    const comments = result.recordset.map((comment) => ({
      ...comment,
      created_at: formatBeijingTime(comment.created_at),
    }));

    res.status(200).json({
      success: true,
      data: { comments },
    });
  } catch (err) {
    console.error("获取用户评论错误:", err);
    res
      .status(500)
      .json({ success: false, message: "服务器错误：" + err.message });
  }
});

// ======================
// 个人中心：修改用户名
// PUT /api/users/:id/username
// ======================
app.put("/api/users/:id/username", async (req, res) => {
  try {
    const pool = await getDbConnection();
    if (!pool) {
      return res
        .status(500)
        .json({ success: false, message: "数据库连接失败" });
    }

    const userId = req.params.id;
    const { new_username, user_id } = req.body;

    // 权限验证
    if (userId != user_id) {
      return res.status(403).json({ success: false, message: "无权限修改" });
    }

    // 用户名重复校验
    const checkUser = await pool
      .request()
      .input("username", sql.NVarChar, new_username)
      .query("SELECT user_id FROM users WHERE username = @username");

    if (checkUser.recordset.length > 0) {
      return res
        .status(400)
        .json({ success: false, message: "用户名已被占用" });
    }

    // 执行更新
    await pool
      .request()
      .input("userId", sql.Int, userId)
      .input("newUsername", sql.NVarChar, new_username)
      .query(
        "UPDATE users SET username = @newUsername WHERE user_id = @userId"
      );

    res.status(200).json({ success: true, message: "用户名修改成功" });
  } catch (err) {
    console.error("修改用户名错误:", err);
    res
      .status(500)
      .json({ success: false, message: "服务器错误：" + err.message });
  }
});

// ======================
// 个人中心：修改密码（适配bcrypt加密）
// PUT /api/users/:id/password
// ======================
app.put("/api/users/:id/password", async (req, res) => {
  try {
    const pool = await getDbConnection();
    if (!pool) {
      return res
        .status(500)
        .json({ success: false, message: "数据库连接失败" });
    }

    const userId = req.params.id;
    const { old_password, new_password, user_id } = req.body;

    // 权限验证
    if (userId != user_id) {
      return res.status(403).json({ success: false, message: "无权限修改" });
    }

    // 验证原密码（需用bcrypt解密对比）
    const userResult = await pool
      .request()
      .input("userId", sql.Int, userId)
      .query("SELECT password FROM users WHERE user_id = @userId");

    if (userResult.recordset.length === 0) {
      return res.status(404).json({ success: false, message: "用户不存在" });
    }

    const storedPassword = userResult.recordset[0].password;
    const isPasswordValid = await bcrypt.compare(old_password, storedPassword);
    if (!isPasswordValid) {
      return res.status(400).json({ success: false, message: "原密码错误" });
    }

    // 新密码加密存储
    const salt = await bcrypt.genSalt(10);
    const hashedNewPassword = await bcrypt.hash(new_password, salt);

    // 执行更新
    await pool
      .request()
      .input("userId", sql.Int, userId)
      .input("newPassword", sql.NVarChar, hashedNewPassword)
      .query(
        "UPDATE users SET password = @newPassword WHERE user_id = @userId"
      );

    res.status(200).json({ success: true, message: "密码修改成功" });
  } catch (err) {
    console.error("修改密码错误:", err);
    res
      .status(500)
      .json({ success: false, message: "服务器错误：" + err.message });
  }
});
// ======================
// 4. 静态文件 + 404处理
// ======================
app.use(express.static(staticFilePath));
app.use((req, res) => {
  res.status(404).json({
    message: `接口不存在: ${req.method} ${req.originalUrl}`,
    tip: "请检查URL拼写",
    availableAPIs: [
      "POST /api/register",
      "POST /api/login",
      "GET /api/test",
      "GET /api/posts",
      "POST /api/posts",
      "GET /api/comments",
      "POST /api/comments",
    ],
  });
});

// ======================
// 5. 启动服务器
// ======================
app.listen(port, async () => {
  console.log(`🚀 服务器已启动: http://localhost:${port}`);
  console.log(`📌 前端登录页: http://localhost:${port}/login.html`);
  console.log(`🔍 测试接口: http://localhost:${port}/api/test`);
  // 显示修复后的正确北京时间
  console.log(`🕒 修复后显示的北京时间: ${formatBeijingTime(new Date())}`);
  const isConnected = await getDbConnection();
  if (isConnected) console.log("✅ 数据库连接正常");
  else console.error("❌ 数据库连接失败，请检查配置");
});
