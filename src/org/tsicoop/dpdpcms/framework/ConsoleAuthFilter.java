package org.tsicoop.dpdpcms.framework;

import org.tsicoop.dpdpcms.util.Constants;

import jakarta.servlet.*;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

/**
 * Server-side gate for the static admin/DPO console pages.
 *
 * Previously these pages were served unconditionally (200 OK) to any HTTP client;
 * the only login check was client-side JS reading localStorage after the full page
 * had already been delivered (CWE-602 / CWE-306). This filter runs before the
 * default servlet dispatches the file and requires a valid, non-revoked operator
 * JWT — issued at login and carried in an HttpOnly session cookie so plain browser
 * navigation (not just XHR/fetch) can present it — or the page is never served.
 *
 * This does not change how the API itself authenticates: /api/v1/admin/* and
 * /api/v1/client/* calls continue to be validated independently by
 * InterceptingFilter on every request.
 */
public class ConsoleAuthFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) {
    }

    @Override
    public void destroy() {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        String token = readSessionCookie(req);
        if (token == null || !JWTUtil.isTokenValid(token)) {
            res.sendRedirect("/index.html");
            return;
        }

        chain.doFilter(request, response);
    }

    private String readSessionCookie(HttpServletRequest req) {
        Cookie[] cookies = req.getCookies();
        if (cookies == null) return null;
        for (Cookie c : cookies) {
            if (Constants.CONSOLE_SESSION_COOKIE.equals(c.getName())) {
                return c.getValue();
            }
        }
        return null;
    }
}
