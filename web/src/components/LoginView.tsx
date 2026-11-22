export default function LoginView() {
  return (
    <section className="login-shell">
      <div className="login-card">
        <h1 className="login-card__title">Osmium</h1>
        <p className="login-card__subtitle">
          使用组织身份登录后访问已授权主机的 Web SSH 终端。
        </p>
        <a id="oidc-login" className="btn btn--primary login-card__cta" href="/auth/login">
          使用 OIDC 登录
        </a>
      </div>
    </section>
  );
}
