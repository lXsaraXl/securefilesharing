import { useState, useEffect } from "react";
import "@/App.css";
import axios from "axios";
import { Toaster, toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Lock, Upload, Download, Share2, Trash2, Shield, Users, Activity, FileText, LogOut, Key } from "lucide-react";

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const API = `${BACKEND_URL}/api`;

function App() {
  const [view, setView] = useState("landing"); // landing, otp, dashboard
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(null);
  const [pendingEmail, setPendingEmail] = useState("");
  const [demoOtp, setDemoOtp] = useState("");
  
  // Files
  const [files, setFiles] = useState([]);
  const [uploading, setUploading] = useState(false);
  
  // Admin
  const [users, setUsers] = useState([]);
  const [logs, setLogs] = useState([]);
  const [stats, setStats] = useState({});
  
  // Dialogs
  const [shareDialog, setShareDialog] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);
  const [shareEmail, setShareEmail] = useState("");

  useEffect(() => {
    const savedToken = localStorage.getItem("token");
    const savedUser = localStorage.getItem("user");
    if (savedToken && savedUser) {
      setToken(savedToken);
      setUser(JSON.parse(savedUser));
      setView("dashboard");
    }
  }, []);

  useEffect(() => {
    if (view === "dashboard" && token) {
      loadFiles();
      if (user?.role === "admin") {
        loadAdminData();
      }
    }
  }, [view, token]);

  const axiosConfig = () => ({
    headers: { Authorization: `Bearer ${token}` }
  });

  // ========== AUTH ==========

  const handleRegister = async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    try {
      const res = await axios.post(`${API}/auth/register`, {
        email: formData.get("email"),
        password: formData.get("password"),
        full_name: formData.get("full_name"),
        role: formData.get("role") || "user"
      });
      toast.success("Registration successful! Please login.");
      document.getElementById("login-tab-trigger").click();
    } catch (err) {
      toast.error(err.response?.data?.detail || "Registration failed");
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const email = formData.get("email");
    try {
      const res = await axios.post(`${API}/auth/login`, {
        email,
        password: formData.get("password")
      });
      setPendingEmail(email);
      setDemoOtp(res.data.otp_for_demo);
      toast.success("OTP sent to your email!");
      setView("otp");
    } catch (err) {
      toast.error(err.response?.data?.detail || "Login failed");
    }
  };

  const handleVerifyOTP = async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const otp = formData.get("otp");
    try {
      const res = await axios.post(`${API}/auth/verify-otp`, {
        email: pendingEmail,
        otp
      });
      setToken(res.data.access_token);
      setUser(res.data.user);
      localStorage.setItem("token", res.data.access_token);
      localStorage.setItem("user", JSON.stringify(res.data.user));
      toast.success("Login successful!");
      setView("dashboard");
    } catch (err) {
      toast.error(err.response?.data?.detail || "Invalid OTP");
    }
  };

  const handleResendOTP = async () => {
    try {
      const res = await axios.post(`${API}/auth/resend-otp`, { email: pendingEmail });
      setDemoOtp(res.data.otp_for_demo);
      toast.success("OTP resent!");
    } catch (err) {
      toast.error("Failed to resend OTP");
    }
  };

  const handleLogout = () => {
    setToken(null);
    setUser(null);
    localStorage.removeItem("token");
    localStorage.removeItem("user");
    setView("landing");
    toast.success("Logged out successfully");
  };

  // ========== FILES ==========

  const loadFiles = async () => {
    try {
      const res = await axios.get(`${API}/files/list`, axiosConfig());
      setFiles(res.data.files);
    } catch (err) {
      toast.error("Failed to load files");
    }
  };

  const handleUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    
    setUploading(true);
    const formData = new FormData();
    formData.append("file", file);
    
    try {
      const res = await axios.post(`${API}/files/upload`, formData, axiosConfig());
      toast.success(`File encrypted and uploaded: ${res.data.filename}`);
      loadFiles();
    } catch (err) {
      toast.error(err.response?.data?.detail || "Upload failed");
    } finally {
      setUploading(false);
      e.target.value = "";
    }
  };

  const handleDownload = async (fileId, filename) => {
    try {
      const res = await axios.get(`${API}/files/download/${fileId}`, {
        ...axiosConfig(),
        responseType: "blob"
      });
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", filename);
      document.body.appendChild(link);
      link.click();
      link.remove();
      toast.success("File downloaded and decrypted");
    } catch (err) {
      toast.error("Download failed");
    }
  };

  const handleDelete = async (fileId) => {
    if (!window.confirm("Delete this file?")) return;
    try {
      await axios.delete(`${API}/files/delete/${fileId}`, axiosConfig());
      toast.success("File deleted");
      loadFiles();
    } catch (err) {
      toast.error("Delete failed");
    }
  };

  const handleShare = async () => {
    if (!shareEmail) {
      toast.error("Enter an email");
      return;
    }
    try {
      await axios.post(`${API}/files/share/${selectedFile.id}`, { email: shareEmail }, axiosConfig());
      toast.success(`File shared with ${shareEmail}`);
      setShareDialog(false);
      setShareEmail("");
      loadFiles();
    } catch (err) {
      toast.error(err.response?.data?.detail || "Share failed");
    }
  };

  // ========== ADMIN ==========

  const loadAdminData = async () => {
    try {
      const [usersRes, logsRes, statsRes] = await Promise.all([
        axios.get(`${API}/admin/users`, axiosConfig()),
        axios.get(`${API}/admin/logs`, axiosConfig()),
        axios.get(`${API}/admin/stats`, axiosConfig())
      ]);
      setUsers(usersRes.data.users);
      setLogs(logsRes.data.logs);
      setStats(statsRes.data);
    } catch (err) {
      console.error("Failed to load admin data", err);
    }
  };

  // ========== VIEWS ==========

  if (view === "landing") {
    return (
      <div className="app-container">
        <Toaster position="top-right" richColors />
        
        {/* Header */}
        <header className="header">
          <div className="header-content">
            <div className="logo">
              <Shield className="logo-icon" />
              <span className="logo-text">SecureShare</span>
            </div>
          </div>
        </header>

        {/* Hero */}
        <section className="hero">
          <div className="hero-content">
            <div className="hero-badge">
              <Lock size={16} />
              <span>AES-256 & RSA Encryption</span>
            </div>
            <h1 className="hero-title">
              Enterprise-Grade
              <br />
              <span className="hero-title-gradient">Secure File Sharing</span>
            </h1>
            <p className="hero-description">
              Military-grade encryption with multi-factor authentication and role-based access control.
              Your files, protected by cryptographic excellence.
            </p>
            <div className="hero-features">
              <div className="feature-item">
                <Key size={20} />
                <span>AES-256 Encryption</span>
              </div>
              <div className="feature-item">
                <Shield size={20} />
                <span>RSA Key Exchange</span>
              </div>
              <div className="feature-item">
                <Activity size={20} />
                <span>Multi-Factor Auth</span>
              </div>
            </div>
          </div>

          <div className="auth-card-container">
            <Card className="auth-card">
              <Tabs defaultValue="login" className="auth-tabs">
                <TabsList className="auth-tabs-list">
                  <TabsTrigger value="login" id="login-tab-trigger" data-testid="login-tab">Login</TabsTrigger>
                  <TabsTrigger value="register" data-testid="register-tab">Register</TabsTrigger>
                </TabsList>
                
                <TabsContent value="login" data-testid="login-form">
                  <CardHeader>
                    <CardTitle>Welcome Back</CardTitle>
                    <CardDescription>Enter your credentials to access your secure vault</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <form onSubmit={handleLogin} className="auth-form">
                      <div className="form-group">
                        <Label htmlFor="login-email">Email</Label>
                        <Input
                          id="login-email"
                          name="email"
                          type="email"
                          placeholder="you@example.com"
                          required
                          data-testid="login-email-input"
                        />
                      </div>
                      <div className="form-group">
                        <Label htmlFor="login-password">Password</Label>
                        <Input
                          id="login-password"
                          name="password"
                          type="password"
                          placeholder="••••••••"
                          required
                          data-testid="login-password-input"
                        />
                      </div>
                      <Button type="submit" className="submit-btn" data-testid="login-submit-btn">
                        Login
                      </Button>
                    </form>
                  </CardContent>
                </TabsContent>
                
                <TabsContent value="register" data-testid="register-form">
                  <CardHeader>
                    <CardTitle>Create Account</CardTitle>
                    <CardDescription>Start securing your files today</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <form onSubmit={handleRegister} className="auth-form">
                      <div className="form-group">
                        <Label htmlFor="register-name">Full Name</Label>
                        <Input
                          id="register-name"
                          name="full_name"
                          type="text"
                          placeholder="John Doe"
                          required
                          data-testid="register-name-input"
                        />
                      </div>
                      <div className="form-group">
                        <Label htmlFor="register-email">Email</Label>
                        <Input
                          id="register-email"
                          name="email"
                          type="email"
                          placeholder="you@example.com"
                          required
                          data-testid="register-email-input"
                        />
                      </div>
                      <div className="form-group">
                        <Label htmlFor="register-password">Password</Label>
                        <Input
                          id="register-password"
                          name="password"
                          type="password"
                          placeholder="••••••••"
                          required
                          data-testid="register-password-input"
                        />
                      </div>
                      <div className="form-group">
                        <Label htmlFor="register-role">Role</Label>
                        <select
                          id="register-role"
                          name="role"
                          className="role-select"
                          data-testid="register-role-select"
                        >
                          <option value="user">User</option>
                          <option value="admin">Admin</option>
                        </select>
                      </div>
                      <Button type="submit" className="submit-btn" data-testid="register-submit-btn">
                        Create Account
                      </Button>
                    </form>
                  </CardContent>
                </TabsContent>
              </Tabs>
            </Card>
          </div>
        </section>
      </div>
    );
  }

  if (view === "otp") {
    return (
      <div className="app-container otp-view">
        <Toaster position="top-right" richColors />
        <div className="otp-container">
          <Card className="otp-card">
            <CardHeader>
              <div className="otp-icon">
                <Shield size={48} />
              </div>
              <CardTitle>Multi-Factor Authentication</CardTitle>
              <CardDescription>
                Enter the 6-digit code sent to {pendingEmail}
              </CardDescription>
            </CardHeader>
            <CardContent>
              {demoOtp && (
                <div className="demo-otp" data-testid="demo-otp-display">
                  <strong>Demo OTP:</strong> {demoOtp}
                </div>
              )}
              <form onSubmit={handleVerifyOTP} className="otp-form">
                <div className="form-group">
                  <Label htmlFor="otp-input">OTP Code</Label>
                  <Input
                    id="otp-input"
                    name="otp"
                    type="text"
                    placeholder="000000"
                    maxLength={6}
                    required
                    data-testid="otp-input"
                    className="otp-input"
                  />
                </div>
                <Button type="submit" className="submit-btn" data-testid="verify-otp-btn">
                  Verify & Login
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  onClick={handleResendOTP}
                  className="resend-btn"
                  data-testid="resend-otp-btn"
                >
                  Resend OTP
                </Button>
              </form>
            </CardContent>
          </Card>
        </div>
      </div>
    );
  }

  if (view === "dashboard") {
    return (
      <div className="dashboard-container">
        <Toaster position="top-right" richColors />
        
        {/* Dashboard Header */}
        <header className="dashboard-header">
          <div className="dashboard-header-content">
            <div className="logo">
              <Shield className="logo-icon" />
              <span className="logo-text">SecureShare</span>
            </div>
            <div className="user-info">
              <Badge variant="outline" className="role-badge" data-testid="user-role-badge">
                {user?.role?.toUpperCase()}
              </Badge>
              <span className="user-email" data-testid="user-email-display">{user?.email}</span>
              <Button variant="ghost" size="sm" onClick={handleLogout} data-testid="logout-btn">
                <LogOut size={16} />
              </Button>
            </div>
          </div>
        </header>

        <div className="dashboard-content">
          <Tabs defaultValue="files" className="dashboard-tabs">
            <TabsList className="dashboard-tabs-list">
              <TabsTrigger value="files" data-testid="files-tab">
                <FileText size={16} />
                My Files
              </TabsTrigger>
              {user?.role === "admin" && (
                <>
                  <TabsTrigger value="users" data-testid="users-tab">
                    <Users size={16} />
                    Users
                  </TabsTrigger>
                  <TabsTrigger value="logs" data-testid="logs-tab">
                    <Activity size={16} />
                    Activity Logs
                  </TabsTrigger>
                </>
              )}
            </TabsList>

            {/* Files Tab */}
            <TabsContent value="files" className="files-tab-content" data-testid="files-content">
              <div className="files-header">
                <h2>Encrypted Files</h2>
                <div className="upload-section">
                  <input
                    type="file"
                    id="file-upload"
                    onChange={handleUpload}
                    style={{ display: "none" }}
                    data-testid="file-upload-input"
                  />
                  <Button
                    onClick={() => document.getElementById("file-upload").click()}
                    disabled={uploading}
                    data-testid="upload-btn"
                  >
                    <Upload size={16} />
                    {uploading ? "Encrypting..." : "Upload File"}
                  </Button>
                </div>
              </div>

              <div className="files-grid">
                {files.length === 0 ? (
                  <div className="empty-state" data-testid="empty-files-message">
                    <FileText size={48} />
                    <p>No files yet. Upload your first encrypted file!</p>
                  </div>
                ) : (
                  files.map((file) => (
                    <Card key={file.id} className="file-card" data-testid={`file-card-${file.id}`}>
                      <CardHeader>
                        <CardTitle className="file-name" data-testid={`file-name-${file.id}`}>{file.filename}</CardTitle>
                        <CardDescription>
                          <div className="file-meta">
                            <span>Owner: {file.owner_email}</span>
                            <span>Size: {(file.size / 1024).toFixed(2)} KB</span>
                          </div>
                        </CardDescription>
                      </CardHeader>
                      <CardContent>
                        <div className="file-hash" data-testid={`file-hash-${file.id}`}>
                          <strong>Hash:</strong> {file.original_hash.substring(0, 16)}...
                        </div>
                        {file.shared_with?.length > 0 && (
                          <div className="shared-info" data-testid={`shared-info-${file.id}`}>
                            <Badge variant="secondary">Shared with {file.shared_with.length}</Badge>
                          </div>
                        )}
                        <div className="file-actions">
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => handleDownload(file.id, file.filename)}
                            data-testid={`download-btn-${file.id}`}
                          >
                            <Download size={14} />
                          </Button>
                          {file.owner_email === user?.email && (
                            <>
                              <Button
                                size="sm"
                                variant="outline"
                                onClick={() => {
                                  setSelectedFile(file);
                                  setShareDialog(true);
                                }}
                                data-testid={`share-btn-${file.id}`}
                              >
                                <Share2 size={14} />
                              </Button>
                              <Button
                                size="sm"
                                variant="destructive"
                                onClick={() => handleDelete(file.id)}
                                data-testid={`delete-btn-${file.id}`}
                              >
                                <Trash2 size={14} />
                              </Button>
                            </>
                          )}
                        </div>
                      </CardContent>
                    </Card>
                  ))
                )}
              </div>
            </TabsContent>

            {/* Admin: Users Tab */}
            {user?.role === "admin" && (
              <TabsContent value="users" data-testid="users-content">
                <h2>System Users</h2>
                <div className="stats-grid">
                  <Card>
                    <CardHeader>
                      <CardTitle>Total Users</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="stat-value" data-testid="total-users-stat">{stats.total_users || 0}</div>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardHeader>
                      <CardTitle>Total Files</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="stat-value" data-testid="total-files-stat">{stats.total_files || 0}</div>
                    </CardContent>
                  </Card>
                  <Card>
                    <CardHeader>
                      <CardTitle>Total Actions</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="stat-value" data-testid="total-logs-stat">{stats.total_logs || 0}</div>
                    </CardContent>
                  </Card>
                </div>
                <ScrollArea className="users-list">
                  {users.map((u) => (
                    <Card key={u.id} className="user-card" data-testid={`user-card-${u.id}`}>
                      <CardContent>
                        <div className="user-card-content">
                          <div>
                            <strong data-testid={`user-name-${u.id}`}>{u.full_name}</strong>
                            <p data-testid={`user-email-${u.id}`}>{u.email}</p>
                          </div>
                          <Badge data-testid={`user-role-${u.id}`}>{u.role}</Badge>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </ScrollArea>
              </TabsContent>
            )}

            {/* Admin: Logs Tab */}
            {user?.role === "admin" && (
              <TabsContent value="logs" data-testid="logs-content">
                <h2>Activity Logs</h2>
                <ScrollArea className="logs-list">
                  {logs.map((log, idx) => (
                    <Card key={log.id || idx} className="log-card" data-testid={`log-card-${idx}`}>
                      <CardContent>
                        <div className="log-card-content">
                          <div>
                            <strong data-testid={`log-action-${idx}`}>{log.action}</strong>
                            <p data-testid={`log-user-${idx}`}>{log.user_email}</p>
                            {log.filename && <p data-testid={`log-filename-${idx}`}>File: {log.filename}</p>}
                          </div>
                          <span className="log-timestamp" data-testid={`log-timestamp-${idx}`}>
                            {new Date(log.timestamp).toLocaleString()}
                          </span>
                        </div>
                      </CardContent>
                    </Card>
                  ))}
                </ScrollArea>
              </TabsContent>
            )}
          </Tabs>
        </div>

        {/* Share Dialog */}
        <Dialog open={shareDialog} onOpenChange={setShareDialog}>
          <DialogContent data-testid="share-dialog">
            <DialogHeader>
              <DialogTitle>Share File</DialogTitle>
              <DialogDescription>
                Share "{selectedFile?.filename}" with another user
              </DialogDescription>
            </DialogHeader>
            <div className="share-form">
              <Label htmlFor="share-email">User Email</Label>
              <Input
                id="share-email"
                type="email"
                placeholder="user@example.com"
                value={shareEmail}
                onChange={(e) => setShareEmail(e.target.value)}
                data-testid="share-email-input"
              />
              <Button onClick={handleShare} className="share-submit-btn" data-testid="share-submit-btn">
                Share File
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>
    );
  }

  return null;
}

export default App;