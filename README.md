
# 🧱 blackblock — Ultimate Java L7 HTTP Filter

**blackblock** is a powerful Java middleware for filtering malicious Layer 7 HTTP traffic with ASN, header, method, version, and user-agent intelligence.  
Built for performance, stealth, and total web protection.

---

## 🚨 What blackblock Does

This filter drops suspicious HTTP requests before they ever reach your app.

### 🛡️ It blocks:
- Dangerous HTTP methods: `PUT`, `DELETE`, `PATCH`, `OPTIONS`, `PURGE`
- Bad or empty user-agents: `curl`, `wget`, `python`, `java`, `Slik`, `NT 6.2`, `NT 5.1`, etc.
- Suspicious URI strings: `$`, `%`, `@`, `~`, `rand`
- Legacy and malformed HTTP versions: `HTTP/1.0`, `HTTP/1.1`, `HTTP/1.2`
- ASN-based filtering: blocks over 80+ known abuse ASNs
- Malformed `X-Forwarded-For` headers
- Threat scores (via optional `X-Threat-Score` header)
- Invalid countries or continents: `T1`, `XX`
- Requests that don’t identify as `Mozilla/5.0`

---

## 🧬 Example Integration (Servlet Filter)

```java
@WebFilter("/*")
public class BlackBlockFilter implements Filter {
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
        throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        if (BlackBlock.shouldBlock(req)) {
            res.setStatus(403);
            res.getWriter().write("Blocked by blackblock 🧱");
            return;
        }

        chain.doFilter(request, response);
    }
}
```

---

## 📦 Deployment

1. Drop `blackblock.java` into your web app
2. Hook into your filter chain
3. Optionally pass Cloudflare headers like:
   - `CF-IPCountry`
   - `CF-IPContinent`
   - `CF-IPCountry-ASN`
   - `X-Threat-Score`

---

## 🧪 Tested On

- Apache Tomcat 9+
- Java Servlet 4.0+
- Spring Boot (as a custom filter bean)

---

## 🧠 Advanced Mode

Use custom headers for scoring or proxy metadata:
- `X-Threat-Score`: any numeric value ≥5 = block
- `CF-IPCountry-ASN`: ASN number to match blocklist
- `CF-IPContinent`, `CF-IPCountry`: for GeoIP logic

---

## 📄 License

MIT — Free to use, fork, and level up 🔓  
Crafted with precision by [h2socket](https://github.com/h2socket)

---

Protect your app like a fortress. Activate blackblock. 🧱🛡️
