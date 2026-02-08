public enum AccessHeader {
    public static let accessToken = "Cf-Access-Token"
    public static let clientID = "Cf-Access-Client-Id"
    public static let clientSecret = "Cf-Access-Client-Secret"
    public static let jumpDestination = "Cf-Access-Jump-Destination"

    public static let appDomain = "CF-Access-Domain"
    public static let appAUD = "CF-Access-Aud"
}

public enum AccessPath {
    public static let login = "/cdn-cgi/access/login"
}
