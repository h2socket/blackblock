
import javax.servlet.http.HttpServletRequest;
import java.util.*;

public class BlackBlock {
    private static final Set<String> blockedUserAgents = new HashSet<>(Arrays.asList(
        "curl", "wget", "python", "java", "Slik", "ALittle", ".NET", "LM-Q", "NT 6.2", "NT 6.3", "NT 5.1"
    ));

    private static final Set<String> blockedMethods = new HashSet<>(Arrays.asList(
        "PUT", "PATCH", "DELETE", "OPTIONS", "PURGE"
    ));

    private static final List<String> suspiciousUriPatterns = Arrays.asList("$", "%", "@", "~", "rand");

    private static final Set<String> invalidUserAgents = new HashSet<>(Arrays.asList(
        "", " ", "-", "'"
    ));

    private static final Set<String> blockedASNs = new HashSet<>(Arrays.asList(
        "51167", "14061", "16276", "24940", "8075", "200373", "8560", "60729", "26548", "210848", "9087", "4837",
        "44477", "210644", "132203", "40021", "60223", "174", "3236", "4134", "4766", "5650", "6939", "7203",
        "7713", "12252", "12586", "14576", "14618", "16509", "17552", "17676", "18779", "20278", "20473",
        "21769", "22612", "23470", "28840", "31898", "32505", "33387", "35048", "35624", "35830", "35913",
        "36352", "37963", "38136", "40676", "43624", "44066", "45102", "45899", "46573", "49505", "52000",
        "54252", "55081", "55256", "55286", "59441", "62005", "62240", "63949", "64267", "200000", "206092",
        "207633", "207728", "212238", "265465", "265579", "271806", "396982", "397630", "211720", "271633",
        "266542", "45317", "17054", "577", "24961"
    ));

    private static final Set<String> blockedContinents = new HashSet<>(Arrays.asList("T1", "XX"));
    private static final Set<String> blockedCountries = new HashSet<>(Arrays.asList("T1", "XX"));

    private static final Set<String> invalidHttpVersions = new HashSet<>(Arrays.asList("HTTP/1.2"));

    public static boolean shouldBlock(HttpServletRequest req) {
        if (blockedMethods.contains(req.getMethod())) return true;

        String ua = Optional.ofNullable(req.getHeader("User-Agent")).orElse("");
        String uaLower = ua.toLowerCase();
        for (String bad : blockedUserAgents) {
            if (uaLower.contains(bad.toLowerCase())) return true;
        }
        if (invalidUserAgents.contains(ua)) return true;
        if (!ua.contains("Mozilla/5.0")) return true;

        String ver = req.getProtocol();
        if (invalidHttpVersions.contains(ver)) return true;
        if ((ver.equals("HTTP/1.0") || ver.equals("HTTP/1.1")) && uaLower.contains("java")) return true;

        String uri = req.getRequestURI();
        for (String p : suspiciousUriPatterns) {
            if (uri.contains(p)) return true;
        }

        String xff = Optional.ofNullable(req.getHeader("X-Forwarded-For")).orElse("");
        if (xff.contains("192.0.") || xff.contains(".0.0")) return true;

        String asn = Optional.ofNullable(req.getHeader("CF-IPCountry-ASN")).orElse("");
        if (blockedASNs.contains(asn)) return true;

        String continent = Optional.ofNullable(req.getHeader("CF-IPContinent")).orElse("");
        String country = Optional.ofNullable(req.getHeader("CF-IPCountry")).orElse("");
        if (blockedContinents.contains(continent) || blockedCountries.contains(country)) return true;
        if (country.equals("T1") && ua.isEmpty()) return true;
        if (continent.equals("T1") || country.equals("T1")) return true;

        if (asn.equals("8075") || asn.equals("6939") || asn.equals("54252") || asn.equals("64267")) return true;
        if (asn.equals("24961") && !ver.equals("HTTP/3")) return true;

        String threatScore = Optional.ofNullable(req.getHeader("X-Threat-Score")).orElse("0");
        try {
            int score = Integer.parseInt(threatScore);
            if (score >= 5) return true;
        } catch (NumberFormatException ignored) {}

        return false;
    }
}
