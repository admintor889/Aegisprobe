/**
 * Local multi-role target for authorization testing.
 *
 * Intentional vulnerabilities:
 * - GET /api/orders/:id has no ownership or tenant check (BOLA/IDOR).
 * - GET /api/admin/users and /api/admin/users/:id have no role check (BFLA).
 * - PATCH /api/users/:id accepts role and tenant fields (mass assignment).
 *
 * The agent must discover and reason from observed routes/auth contexts. Do not
 * hardcode this target name or these paths into agent decision logic.
 */

const express = require("express");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");

const JWT_SECRET = process.env.JWT_SECRET || "local-smoke-jwt-secret-do-not-use-in-prod";
const DEFAULT_PORT = Number.parseInt(process.env.PORT || "3100", 10);

function seedUsers() {
  return [
    { id: 1, username: "alice", password: "alice123", role: "customer", tenant: "tenant-a", email: "alice@example.com", createdAt: "2024-01-15" },
    { id: 2, username: "bob", password: "bob123", role: "customer", tenant: "tenant-b", email: "bob@example.com", createdAt: "2024-02-20" },
    { id: 3, username: "admin", password: "admin123", role: "admin", tenant: null, email: "admin@example.com", createdAt: "2023-06-01" }
  ];
}

function seedOrders() {
  return [
    { id: 101, userId: 1, tenant: "tenant-a", status: "shipped", amount: 49.99, items: ["widget-a", "widget-b"], createdAt: "2024-05-10" },
    { id: 102, userId: 2, tenant: "tenant-b", status: "processing", amount: 129.50, items: ["gadget-x"], createdAt: "2024-06-01" },
    { id: 103, userId: 1, tenant: "tenant-a", status: "delivered", amount: 9.99, items: ["cable-c"], createdAt: "2024-06-15" },
    { id: 104, userId: 2, tenant: "tenant-b", status: "pending", amount: 79.0, items: ["widget-c", "adapter-d"], createdAt: "2024-07-01" }
  ];
}

function createApp() {
  const app = express();
  const state = {
    users: seedUsers(),
    orders: seedOrders(),
    hits: []
  };

  app.locals.state = state;
  app.use(bodyParser.json());
  app.use(bodyParser.urlencoded({ extended: true }));
  app.use((req, _res, next) => {
    state.hits.push(`${req.method} ${req.path}`);
    next();
  });

  function authMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Unauthorized", message: "Missing or invalid Authorization header" });
    }
    try {
      const token = authHeader.slice(7);
      const decoded = jwt.verify(token, JWT_SECRET);
      req.user = state.users.find((user) => user.id === decoded.sub);
      if (!req.user) {
        return res.status(401).json({ error: "Unauthorized", message: "User not found" });
      }
      return next();
    } catch {
      return res.status(401).json({ error: "Unauthorized", message: "Invalid or expired token" });
    }
  }

  app.get("/", (_req, res) => {
    res.type("html").send(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <title>Local Multi-Role App</title>
  <script src="/static/app.js" defer></script>
</head>
<body>
  <h1>Multi-Role Application</h1>
  <nav>
    <a href="/login">Login</a>
    <a href="/api/orders">Orders</a>
    <a href="/api/admin/users">Admin Users</a>
  </nav>
</body>
</html>`);
  });

  app.get("/login", (_req, res) => {
    res.type("html").send(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8" /><title>Login - Multi-Role App</title></head>
<body>
  <form action="/api/login" method="POST">
    <input type="text" name="username" />
    <input type="password" name="password" />
    <button type="submit">Login</button>
  </form>
</body>
</html>`);
  });

  app.get("/static/app.js", (_req, res) => {
    res.type("application/javascript").send(`const apiBase="/api";
const configPath="/static/config/app.json";
const routeMap={
  me:apiBase+"/me",
  orders:apiBase+"/orders",
  orderDetail:apiBase+"/orders/101?include=items",
  adminUsers:apiBase+"/admin/users/1",
  refund:apiBase+"/orders/101/refund",
  updateUser:apiBase+"/users/1"
};
fetch(routeMap.me);
fetch(routeMap.orders);
fetch(routeMap.orderDetail);
import("./admin.chunk.js").then((module)=>module.loadAdminPanel && module.loadAdminPanel());
//# sourceMappingURL=app.js.map
`);
  });

  app.get("/static/admin.chunk.js", (_req, res) => {
    res.type("application/javascript").send(`export function loadAdminPanel(){
  return fetch("/api/admin/users/1").then((response)=>response.json());
}`);
  });

  app.get("/static/app.js.map", (_req, res) => {
    res.json({
      version: 3,
      file: "app.js",
      sources: ["webpack://src/api/routes.ts", "webpack://src/admin/panel.ts"],
      sourcesContent: [
        [
          "export const orderDetail = '/api/orders/102?include=items';",
          "export const userPatch = { method: 'PATCH', url: '/api/users/1', body: { role: 'admin', tenant: 'tenant-a' } };",
          "export const refundPath = '/api/orders/101/refund';",
          "export const fakePrivateKey = '-----BEGIN PRIVATE KEY-----\\nMIIBFAKELOCALTESTKEYONLY\\n-----END PRIVATE KEY-----';"
        ].join("\n"),
        [
          "export function adminUser(){ return fetch('/api/admin/users/1'); }",
          "export function allUsers(){ return fetch('/api/admin/users'); }"
        ].join("\n")
      ],
      mappings: ""
    });
  });

  app.get("/.well-known/security.txt", (_req, res) => {
    res.type("text/plain").send("Contact: security@example.invalid\nPolicy: https://example.invalid/security\n");
  });

  app.get("/.well-known/openid-configuration", (_req, res) => {
    res.json({
      issuer: "http://localhost",
      authorization_endpoint: "/oauth/authorize",
      token_endpoint: "/oauth/token"
    });
  });

  app.get("/__hits", (_req, res) => {
    res.json({ hits: state.hits });
  });

  app.post("/api/login", (req, res) => {
    const { username, password } = req.body;
    const user = state.users.find((candidate) => candidate.username === username && candidate.password === password);
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    const token = jwt.sign({ sub: user.id, username: user.username, role: user.role, tenant: user.tenant }, JWT_SECRET, { expiresIn: "1h" });
    return res.json({ token, user: publicUser(user) });
  });

  app.get("/api/me", authMiddleware, (req, res) => {
    res.json(publicUser(req.user));
  });

  app.get("/api/orders", authMiddleware, (req, res) => {
    const userOrders = req.user.role === "admin"
      ? state.orders
      : state.orders.filter((order) => order.tenant === req.user.tenant);
    res.json({ orders: userOrders.map((order) => ({ id: order.id, status: order.status, amount: order.amount, tenant: order.tenant })) });
  });

  app.get("/api/orders/:id", authMiddleware, (req, res) => {
    const order = state.orders.find((candidate) => candidate.id === Number.parseInt(req.params.id, 10));
    if (!order) {
      return res.status(404).json({ error: "Order not found" });
    }
    res.json({ order });
  });

  app.post("/api/orders/:id/refund", authMiddleware, (req, res) => {
    const order = state.orders.find((candidate) => candidate.id === Number.parseInt(req.params.id, 10));
    if (!order) {
      return res.status(404).json({ error: "Order not found" });
    }
    if (order.userId !== req.user.id) {
      return res.status(403).json({ error: "Forbidden", message: "You can only refund your own orders" });
    }
    if (order.status === "refunded") {
      return res.status(409).json({ error: "Conflict", message: "Order already refunded" });
    }
    order.status = "refunded";
    res.json({ message: "Refund processed", order: { id: order.id, status: order.status } });
  });

  app.get("/api/admin/users", authMiddleware, (_req, res) => {
    res.json({ users: state.users.map(publicUser) });
  });

  app.get("/api/admin/users/:id", authMiddleware, (req, res) => {
    const user = state.users.find((candidate) => candidate.id === Number.parseInt(req.params.id, 10));
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    res.json(publicUser(user));
  });

  app.patch("/api/users/:id", authMiddleware, (req, res) => {
    const targetUser = state.users.find((candidate) => candidate.id === Number.parseInt(req.params.id, 10));
    if (!targetUser) {
      return res.status(404).json({ error: "User not found" });
    }
    const updates = req.body;
    if (updates.username !== undefined) targetUser.username = updates.username;
    if (updates.email !== undefined) targetUser.email = updates.email;
    if (updates.role !== undefined) targetUser.role = updates.role;
    if (updates.tenant !== undefined) targetUser.tenant = updates.tenant;
    res.json({ message: "User updated", user: publicUser(targetUser) });
  });

  return app;
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    role: user.role,
    tenant: user.tenant,
    email: user.email,
    createdAt: user.createdAt
  };
}

function listen(port = DEFAULT_PORT, host = "127.0.0.1") {
  const app = createApp();
  const server = app.listen(port, host, () => {
    const address = server.address();
    const actualPort = typeof address === "object" && address ? address.port : port;
    console.log(`[local-multirole-app] listening on http://${host}:${actualPort}`);
    console.log("[local-multirole-app] users: alice(customer/tenant-a), bob(customer/tenant-b), admin(admin)");
  });
  return { app, server };
}

module.exports = {
  createApp,
  listen,
  seedUsers,
  seedOrders
};

if (require.main === module) {
  listen(DEFAULT_PORT);
}
