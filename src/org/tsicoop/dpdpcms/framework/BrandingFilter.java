package org.tsicoop.dpdpcms.framework;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * Rewrites the configured brand name (see {@link BrandConfig}) into served HTML.
 *
 * Static pages under web/ hardcode the default brand "TSI DPDP CMS" (and a few
 * shorter variants — see BrandConfig.tokens()). There is no templating layer to
 * inject a runtime value, so this filter buffers each HTML response, performs a
 * longest-match-first literal substitution, and rewrites Content-Length to match.
 *
 * Passes straight through, with no buffering, whenever BRAND_NAME is unset —
 * i.e. for the overwhelming majority of deployments that keep the default brand.
 */
public class BrandingFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) {
        // Touch BrandConfig now so a misconfigured BRAND_NAME fails deployment
        // immediately (mirrors JWT_SECRET / DB_ENCRYPTION_KEY's fail-fast intent),
        // rather than surfacing lazily on the first page request.
        BrandConfig.name();
    }

    @Override
    public void destroy() {}

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        if (!BrandConfig.isCustomized() || !(response instanceof HttpServletResponse)) {
            chain.doFilter(request, response);
            return;
        }

        HttpServletResponse httpResponse = (HttpServletResponse) response;
        CharResponseWrapper wrapper = new CharResponseWrapper(httpResponse);
        chain.doFilter(request, wrapper);

        byte[] buffered = wrapper.getBufferedBytes();
        String contentType = httpResponse.getContentType();

        if (contentType == null || !contentType.toLowerCase(Locale.ROOT).contains("text/html")) {
            if (buffered.length > 0) {
                httpResponse.getOutputStream().write(buffered);
            }
            return;
        }

        Charset charset = charsetOf(httpResponse.getCharacterEncoding());
        String body = new String(buffered, charset);
        for (String token : BrandConfig.tokens()) {
            body = body.replace(token, BrandConfig.name());
        }

        byte[] rewritten = body.getBytes(charset);
        httpResponse.setContentLength(rewritten.length);
        httpResponse.getOutputStream().write(rewritten);
    }

    private static Charset charsetOf(String encoding) {
        if (encoding == null || encoding.trim().isEmpty()) return StandardCharsets.UTF_8;
        try {
            return Charset.forName(encoding);
        } catch (Exception e) {
            return StandardCharsets.UTF_8;
        }
    }

    /**
     * Buffers the response body in memory instead of writing it to the client, so
     * the filter can rewrite it before the real write happens. Headers and status
     * set by the chain pass straight through to the wrapped response as usual —
     * only the body (getWriter()/getOutputStream()) is intercepted.
     */
    private static class CharResponseWrapper extends HttpServletResponseWrapper {

        private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        private PrintWriter writer;
        private ServletOutputStream outputStream;

        CharResponseWrapper(HttpServletResponse response) {
            super(response);
        }

        @Override
        public PrintWriter getWriter() {
            if (outputStream != null) {
                throw new IllegalStateException("getOutputStream() already called on this response");
            }
            if (writer == null) {
                writer = new PrintWriter(new OutputStreamWriter(buffer, charsetOf(getCharacterEncoding())), true);
            }
            return writer;
        }

        @Override
        public ServletOutputStream getOutputStream() {
            if (writer != null) {
                throw new IllegalStateException("getWriter() already called on this response");
            }
            if (outputStream == null) {
                outputStream = new ServletOutputStream() {
                    @Override
                    public boolean isReady() {
                        return true;
                    }

                    @Override
                    public void setWriteListener(WriteListener writeListener) {
                    }

                    @Override
                    public void write(int b) {
                        buffer.write(b);
                    }
                };
            }
            return outputStream;
        }

        byte[] getBufferedBytes() {
            if (writer != null) {
                writer.flush();
            }
            return buffer.toByteArray();
        }
    }
}
