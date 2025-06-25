import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.util.regex.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

public class FakeDataDetector extends JFrame {
    private final Color WARNING_COLOR = new Color(200, 0, 0); // Dark red
    private final Color SAFE_COLOR = new Color(0, 128, 0); // Dark green
    private final Color SUSPICIOUS_COLOR = new Color(255, 165, 0); // Orange
    private final Color BTN_COLOR = new Color(70, 130, 180); // Steel blue
    
    private final Set<String> TRUSTED_DOMAINS = new HashSet<>() {{
        add("paypal.com");
        add("google.com");
        add("facebook.com");
        add("amazon.com");
        add("microsoft.com");
        add("bankofamerica.com");
        add("chase.com");
        add("wellsfargo.com");
        add("netflix.com");
        add("apple.com");
    }};

    public FakeDataDetector() {
        setTitle("Advanced Fraud Detector");
        setSize(800, 600);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.addTab("URL Analyzer", createLinkPanel());
        tabbedPane.addTab("Message Scanner", createMessagePanel());
        tabbedPane.addTab("Contact Verifier", createContactPanel());
        tabbedPane.addTab("Email Checker", createEmailPanel());
        add(tabbedPane);

        try { 
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName()); 
        } catch (Exception ignored) {}
    }

    // ================= URL Analysis =================
    private JPanel createLinkPanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        JTextField urlField = new JTextField();
        JTextArea resultArea = createResultArea();
        JButton checkBtn = createButton("Analyze URL", e -> analyzeUrl(urlField.getText().trim(), resultArea));

        panel.add(createInputPanel("URL", urlField, checkBtn), BorderLayout.NORTH);
        panel.add(new JScrollPane(resultArea), BorderLayout.CENTER);
        panel.add(createTipsPanel(
            "URL Safety Tips:",
            "• Check for HTTPS (padlock icon)\n" +
            "• Hover before clicking to see real destination\n" +
            "• Watch for misspellings (e.g., 'arnazon.com')\n" +
            "• Avoid shortened links (bit.ly) from unknown senders\n" +
            "• Legitimate sites won't ask for passwords via email"
        ), BorderLayout.SOUTH);
        
        return panel;
    }

    private void analyzeUrl(String url, JTextArea resultArea) {
        if (url.isEmpty()) {
            displayResult(resultArea, "Please enter a URL to check.", false);
            return;
        }
        if (!url.startsWith("http")) url = "https://" + url;

        try {
            URI uri = new URI(url);
            String host = uri.getHost();
            if (host == null) {
                displayResult(resultArea, "WARNING: Invalid URL format!\n- No valid domain detected", false);
                return;
            }

            StringBuilder reasons = new StringBuilder();
            int severity = 0; // 0-3 scale (3 = most severe)

            // Domain trust check
            boolean isTrusted = TRUSTED_DOMAINS.stream().anyMatch(host::endsWith);
            if (!isTrusted && TRUSTED_DOMAINS.stream().anyMatch(d -> host.contains(d.split("\\.")[0]))) {
                reasons.append("- Uses trusted brand name in suspicious context\n");
                severity = Math.max(severity, 3);
            }

            // Phishing patterns
            String[][] checks = {
                {"\\d{8,}", "Contains suspicious number sequence", "2"},
                {"http://(?!https)", "Unsecure HTTP connection", "2"},
                {"(g00gle|facebok|amaz0n|paypa1|micr0soft)", "Misspelled brand name", "3"},
                {"(bit\\.ly|goo\\.gl|tinyurl)", "URL shortener hides destination", "2"},
                {"(security|verify|login|account)\\.(?!("+String.join("|",TRUSTED_DOMAINS)+"))", "Fake security subdomain", "3"},
                {"\\.(xyz|top|club|tk|gq)", "Suspicious top-level domain", "2"},
                {"@", "Contains @ symbol (possible email)", "1"},
                {"//[^/]+@", "Contains credentials in URL", "3"}
            };

            for (String[] check : checks) {
                if (host.matches(".*"+check[0]+".*") || url.matches(".*"+check[0]+".*")) {
                    reasons.append("- ").append(check[1]).append("\n");
                    severity = Math.max(severity, Integer.parseInt(check[2]));
                }
            }

            // Prepare result
            String result;
            if (severity >= 3) {
                result = "🛑 HIGH RISK: Likely phishing attempt!\n" + reasons;
            } else if (severity >= 2) {
                result = "⚠️ SUSPICIOUS: Potential scam\n" + reasons;
            } else if (isTrusted) {
                result = "✅ Trusted domain\n- No obvious threats detected";
            } else {
                result = "ℹ️ No clear threats found\n- Domain not in trusted list";
            }

            displayResult(resultArea, result, severity < 2 && isTrusted);

        } catch (URISyntaxException e) {
            displayResult(resultArea, "ERROR: Invalid URL format\n- " + e.getMessage(), false);
        }
    }

    // ================= Message Analysis =================
    private JPanel createMessagePanel() {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

        JTextArea messageArea = new JTextArea(8, 30);
        JTextArea resultArea = createResultArea();
        JButton checkBtn = createButton("Scan Message", e -> analyzeMessage(messageArea.getText().trim(), resultArea));

        JPanel inputPanel = new JPanel(new BorderLayout());
        inputPanel.add(new JLabel("Paste suspicious message:"), BorderLayout.NORTH);
        inputPanel.add(new JScrollPane(messageArea), BorderLayout.CENTER);
        inputPanel.add(checkBtn, BorderLayout.SOUTH);

        panel.add(inputPanel, BorderLayout.NORTH);
        panel.add(new JScrollPane(resultArea), BorderLayout.CENTER);
        panel.add(createTipsPanel(
            "Message Red Flags:",
            "• Urgent requests for action\n" +
            "• Requests for money/personal info\n" +
            "• Generic greetings ('Dear Customer')\n" +
            "• Poor grammar/spelling\n" +
            "• Too-good-to-be-true offers\n" +
            "• Links to unfamiliar sites\n" +
            "• Requests for OTPs/passwords"
        ), BorderLayout.SOUTH);
        
        return panel;
    }

    private void analyzeMessage(String msg, JTextArea resultArea) {
        if (msg.isEmpty()) {
            displayResult(resultArea, "Please enter a message to analyze.", false);
            return;
        }

        String[][] redFlags = {
            // Romance/Fraud Scams
            {"(?i)(hi dear|hello sweet|my love|dear friend)", "Romance scam greeting", "2"},
            {"(?i)(from (spain|uk|us) but living in (lagos|accra|mumbai))", "Location inconsistency", "3"},
            {"(?i)(send me (money|gift|cash|bitcoin))", "Direct money request", "3"},
            {"(?i)(text me at|call me at|whatsapp me) ?[+\\d]", "Unsolicited contact request", "2"},
            {"[🇪🇸🇬🇧🇺🇸🇳🇬]", "Suspicious flag emoji use", "2"},

            // Phishing/Account Scams
            {"(?i)account.*(suspend|block|verify)", "Fake account alert", "3"},
            {"(?i)bank.*(update|verify|details)", "Bank phishing attempt", "3"},
            {"(?i)urgent|immediate|action required", "Creates false urgency", "2"},
            {"(?i)(password|pin|cvv|otp)", "Requests sensitive info", "3"},

            // Financial Scams
            {"(?i)(free|prize|won|reward|gift)", "Too-good-to-be-true offer", "2"},
            {"(?i)(pay|transfer|deposit).*(money|funds)", "Payment request", "3"},
            {"(?i)government.*(refund|benefit)", "Fake government offer", "2"},

            // Tech Support
            {"(?i)tech.*support.*(call|number)", "Fake tech support", "2"},
            {"(?i)virus.*detected", "Fake virus alert", "2"},

            // General
            {"\\d{10,}", "Long number string (fake reference)", "1"},
            {"(?i)click (here|below|link)", "Encourages blind clicking", "1"}
        };

        StringBuilder reasons = new StringBuilder();
        int severity = 0;

        for (String[] flag : redFlags) {
            if (Pattern.compile(flag[0]).matcher(msg).find()) {
                reasons.append("- ").append(flag[1]).append("\n");
                severity = Math.max(severity, Integer.parseInt(flag[2]));
            }
        }

        String result;
        if (severity >= 3) {
            result = "🛑 HIGH RISK SCAM DETECTED!\n" + reasons +
                    "\nRecommendation: DELETE immediately. Do NOT engage!";
        } else if (severity >= 2) {
            result = "⚠️ SUSPICIOUS MESSAGE\n" + reasons +
                    "\nRecommendation: Verify through official channels";
        } else if (reasons.length() > 0) {
            result = "ℹ️ Potential low-risk issues\n" + reasons +
                    "\nRecommendation: Proceed with caution";
        } else {
            result = "✅ No obvious threats found\n- Still verify unexpected messages";
        }

        displayResult(resultArea, result, severity < 2);
    }

    // ================= Contact Verification =================
private JPanel createContactPanel() {
    JPanel panel = new JPanel(new BorderLayout(10, 10));
    panel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

    JPanel inputPanel = new JPanel(new GridBagLayout());
    GridBagConstraints gbc = new GridBagConstraints();
    gbc.insets = new Insets(5, 5, 5, 5);
    gbc.anchor = GridBagConstraints.WEST;

    // Country code field with example label
    JLabel countryCodeLabel = new JLabel("Country Code (e.g., +1, +44, +91):");
    JTextField countryCodeField = new JTextField(6);
    
    // Phone number field
    JLabel phoneLabel = new JLabel("Phone Number:");
    JTextField phoneField = new JTextField(15);
    
    // Result area with improved styling
    JTextArea resultArea = createResultArea();
    resultArea.setFont(new Font("Monospaced", Font.BOLD, 13));
    
    // Verify button
    JButton checkBtn = createButton("Verify Contact", e -> {
        String countryCode = countryCodeField.getText().trim();
        String phone = phoneField.getText().trim();
        
        if (countryCode.isEmpty() || phone.isEmpty()) {
            displayContactResult(resultArea, "❌ Please enter both country code and phone number", false);
            return;
        }
        
        String analysis = analyzeContact(countryCode, phone);
        boolean isSafe = !analysis.contains("❌") && !analysis.contains("⚠️");
        displayContactResult(resultArea, analysis, isSafe);
    });

    // Layout components
    gbc.gridx = 0; gbc.gridy = 0;
    inputPanel.add(countryCodeLabel, gbc);
    gbc.gridx = 1;
    inputPanel.add(countryCodeField, gbc);
    
    gbc.gridx = 0; gbc.gridy = 1;
    inputPanel.add(phoneLabel, gbc);
    gbc.gridx = 1;
    inputPanel.add(phoneField, gbc);
    
    gbc.gridx = 0; gbc.gridy = 2; gbc.gridwidth = 2; gbc.fill = GridBagConstraints.CENTER;
    inputPanel.add(checkBtn, gbc);

    panel.add(inputPanel, BorderLayout.NORTH);
    panel.add(new JScrollPane(resultArea), BorderLayout.CENTER);
    
    // Tips panel with more detailed information
    panel.add(createTipsPanel(
        "Contact Verification Guide:",
        "✅ Valid Formats:\n" +
        "• US/Canada: +1 555 123 4567\n" +
        "• UK: +44 20 7946 0958\n" +
        "• India: +91 98765 43210\n\n" +
        "❌ Common Scam Patterns:\n" +
        "• Repeating digits: +1 888 888 8888\n" +
        "• Sequential numbers: +44 1234 567890\n" +
        "• Premium-rate numbers: +1 900, +44 0871\n" +
        "• Suspicious country codes: +375, +255\n\n" +
        "ℹ️ Always verify unexpected calls through official websites"
    ), BorderLayout.SOUTH);
    
    return panel;
}

private String analyzeContact(String countryCode, String phone) {
    // Validate country code format first
    if (!countryCode.matches("^\\+[1-9]\\d{0,3}$")) {
        return "❌ INVALID COUNTRY CODE\n" +
               "• Must start with + followed by digits\n" +
               "• Examples: +1 (US), +44 (UK), +91 (India)";
    }

    String cleanPhone = phone.replaceAll("[^0-9]", "");
    String fullNumber = countryCode.substring(1) + cleanPhone; // Remove + for checks
    
    StringBuilder issues = new StringBuilder();
    int severity = 0; // 0 = safe, 1 = warning, 2 = dangerous

    // ====== Country Code Analysis ======
    Map<String, String> highRiskCodes = new LinkedHashMap<>();
    highRiskCodes.put("375", "Belarus (common in scams)");
    highRiskCodes.put("255", "Tanzania");
    highRiskCodes.put("211", "South Sudan");
    highRiskCodes.put("688", "Tuvalu (premium)");
    highRiskCodes.put("882", "International Networks");
    highRiskCodes.put("883", "International Networks");
    
    for (Map.Entry<String, String> entry : highRiskCodes.entrySet()) {
        if (fullNumber.startsWith(entry.getKey())) {
            issues.append("❌ High-risk country code: +").append(entry.getKey())
                 .append(" (").append(entry.getValue()).append(")\n");
            severity = Math.max(severity, 2);
        }
    }

    // Premium-rate number detection
    if (fullNumber.matches("1(900|976|809|758)\\d+")) {
        issues.append("❌ US premium-rate number (+1 900/976/809/758)\n");
        severity = Math.max(severity, 2);
    }
    if (fullNumber.matches("44(871|9[0-9]{2})\\d+")) {
        issues.append("❌ UK premium-rate number (+44 0871/09xx)\n");
        severity = Math.max(severity, 2);
    }

    // ====== Number Pattern Checks ======
    // Repeating digits (more than 5 repeats)
    if (cleanPhone.matches(".*(\\d)\\1{5,}.*")) {
        issues.append("❌ Repeating digits (common in fake numbers)\n");
        severity = Math.max(severity, 2);
    }
    
    // Sequential numbers (3+ sequential digits)
    if (cleanPhone.matches(".*(012|123|234|345|456|567|678|789|987|876|765|654|543|432|321|210).*")) {
        issues.append("⚠️ Sequential numbers (often fake)\n");
        severity = Math.max(severity, 1);
    }
    
    // Multiple zeros
    if (cleanPhone.matches(".*0{4,}.*")) {
        issues.append("⚠️ Multiple zeros (suspicious pattern)\n");
        severity = Math.max(severity, 1);
    }

    // ====== Country-Specific Validation ======
    String cc = countryCode.substring(1); // Remove +
    
    // US/Canada (+1)
    if (cc.equals("1")) {
        if (cleanPhone.length() != 10) {
            issues.append("❌ US/Canada numbers must be 10 digits\n");
            severity = Math.max(severity, 2);
        }
        if (cleanPhone.matches("555\\d{7}")) {
            issues.append("⚠️ 555 prefix is often used for fake numbers\n");
            severity = Math.max(severity, 1);
        }
    }
    // UK (+44)
    else if (cc.equals("44")) {
        if (cleanPhone.length() != 10 && !cleanPhone.matches("7\\d{9}")) { // UK mobile numbers
            issues.append("❌ UK numbers must be 10 digits (or 11 digits starting with 7)\n");
            severity = Math.max(severity, 2);
        }
    }
    // India (+91)
    else if (cc.equals("91")) {
        if (cleanPhone.length() != 10) {
            issues.append("❌ Indian numbers must be 10 digits\n");
            severity = Math.max(severity, 2);
        }
        if (!cleanPhone.matches("[6-9]\\d{9}")) {
            issues.append("⚠️ Should start with 6-9 for mobile numbers\n");
            severity = Math.max(severity, 1);
        }
    }
    // Other international numbers
    else {
        if (cleanPhone.length() < 5 || cleanPhone.length() > 15) {
            issues.append("⚠️ Suspicious length for international number\n");
            severity = Math.max(severity, 1);
        }
    }

    // ====== Final Evaluation ======
    if (severity == 0) {
        return "✅ VALID PHONE NUMBER\n" +
               "• Country Code: +" + cc + "\n" +
               "• Number: " + formatPhoneNumber(cleanPhone, cc) + "\n" +
               "• No issues detected";
    } else if (severity == 1) {
        return "⚠️ SUSPICIOUS NUMBER\n" + issues.toString() + 
               "• Formatted: " + formatPhoneNumber(cleanPhone, cc) + "\n" +
               "Avoid this Contact & Be Carefull!!!";
    } else {
        return "❌ HIGH-RISK NUMBER DETECTED\n" + issues.toString() + 
               "• Formatted: " + formatPhoneNumber(cleanPhone, cc) + "\n" +
               "Recommendation: DO NOT call or share information";
    }
}

private String formatPhoneNumber(String digits, String countryCode) {
    // Format phone numbers based on country
    switch (countryCode) {
        case "1": // US/Canada
            return String.format("+1 (%s) %s-%s", 
                digits.substring(0, 3), 
                digits.substring(3, 6), 
                digits.substring(6));
        case "44": // UK
            return String.format("+44 %s %s", 
                digits.substring(0, digits.length() == 10 ? 4 : 5), 
                digits.substring(digits.length() == 10 ? 4 : 5));
        case "91": // India
            return String.format("+91 %s %s", 
                digits.substring(0, 5), 
                digits.substring(5));
        default:
            return "+" + countryCode + " " + digits;
    }
}

private void displayContactResult(JTextArea area, String text, boolean isSafe) {
    area.setText(text);
    if (text.contains("❌")) {
        area.setForeground(WARNING_COLOR);
        area.setFont(new Font("Monospaced", Font.BOLD, 14));
    } else if (text.contains("⚠️")) {
        area.setForeground(SUSPICIOUS_COLOR);
        area.setFont(new Font("Monospaced", Font.BOLD, 13));
    } else {
        area.setForeground(SAFE_COLOR);
        area.setFont(new Font("Monospaced", Font.PLAIN, 13));
    }
}

    // ================= Email Analysis =================
private JPanel createEmailPanel() {
    JPanel panel = new JPanel(new BorderLayout(10, 10));
    panel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));

    JTextField emailField = new JTextField();
    JTextArea resultArea = createResultArea();
    JButton checkBtn = createButton("Verify Email", e -> {
        String email = emailField.getText().trim();
        if (email.isEmpty()) {
            displayResult(resultArea, "Please enter an email address.", false);
            return;
        }
        
        // Enhanced email analysis
        String analysis = analyzeEmail(email);
        boolean isSafe = !analysis.contains("🛑") && !analysis.contains("⚠️");
        displayResult(resultArea, analysis, isSafe);
    });

    panel.add(createInputPanel("Email Address", emailField, checkBtn), BorderLayout.NORTH);
    panel.add(new JScrollPane(resultArea), BorderLayout.CENTER);
    panel.add(createTipsPanel(
        "Advanced Email Verification:",
        "• Check for exact domain matches (@paypal.com vs @paypal-security.com)\n" +
        "• Look for subtle misspellings (@gmai1.com instead of @gmail.com)\n" +
        "• Watch for subdomains masking as real companies\n" +
        "• Be wary of emails from free domains for business communications\n" +
        "• Check for inconsistent sender names vs email addresses"
    ), BorderLayout.SOUTH);
    
    return panel;
}

private String analyzeEmail(String email) {
    // Strict email format validation
    if (!email.matches("^[\\w.+%-]+@[\\w.-]+\\.[a-z]{2,10}$")) {
        return "🛑 INVALID FORMAT\n- Email must follow user@domain.com pattern";
    }

    String domain = email.substring(email.indexOf('@') + 1).toLowerCase();
    String username = email.substring(0, email.indexOf('@')).toLowerCase();
    
    StringBuilder reasons = new StringBuilder();
    int severity = 0;

    // ====== Domain Checks ======
    // Disposable email detection
    String[] disposableDomains = {
        "mailinator", "10minutemail", "guerrillamail", "tempmail", 
        "yopmail", "throwaway", "fake", "trashmail", "temp-mail"
    };
    for (String disposable : disposableDomains) {
        if (domain.contains(disposable)) {
            reasons.append("- Disposable email service detected\n");
            severity = Math.max(severity, 3);
            break;
        }
    }

    // Suspicious TLDs
    if (domain.matches(".*\\.(xyz|top|club|tk|gq|ml|cf|ga|rest|buzz|online|cyou)$")) {
        reasons.append("- Suspicious top-level domain (.xyz, .top, etc.)\n");
        severity = Math.max(severity, 2);
    }

    // Brand impersonation
    String[][] brandChecks = {
        {"paypal", "paypa1|paypall|payypal|payapl"},
        {"google", "g00gle|gooogle|gogle|googel"},
        {"microsoft", "micr0soft|mircosoft|mcrosoft"},
        {"amazon", "amaz0n|amzon|amaazon"},
        {"bankofamerica", "bankofamerica|bofa|bankofamer1ca"}
    };
    
    for (String[] brand : brandChecks) {
        if (domain.matches(".*(" + brand[1] + ").*")) {
            reasons.append("- Misspelled ").append(brand[0]).append(" brand name\n");
            severity = Math.max(severity, 3);
        } else if (domain.contains(brand[0]) && !TRUSTED_DOMAINS.contains(domain)) {
            reasons.append("- Uses ").append(brand[0]).append(" name in suspicious domain\n");
            severity = Math.max(severity, 2);
        }
    }

    // Free email providers for business contexts
    if (domain.matches(".*(gmail|yahoo|outlook|hotmail|protonmail)\\.com$") && 
        username.matches(".*(support|admin|service|billing|security).*")) {
        reasons.append("- Business-like username with free email provider\n");
        severity = Math.max(severity, 1);
    }

    // Number sequences
    if (username.matches(".*\\d{5,}.*") || domain.matches(".*\\d{5,}.*")) {
        reasons.append("- Excessive numbers in email/domain\n");
        severity = Math.max(severity, 1);
    }

    // ====== Username Checks ======
    if (username.matches(".*[\\s_]{2,}.*")) {
        reasons.append("- Suspicious spacing/underscores in username\n");
        severity = Math.max(severity, 1);
    }

    // ====== Final Evaluation ======
    boolean isTrusted = TRUSTED_DOMAINS.contains(domain);
    
    if (severity >= 3) {
        return "🛑 HIGH-RISK EMAIL DETECTED\n" + reasons +
               "\nRecommendation: DO NOT engage with this sender";
    } else if (severity >= 2) {
        return "⚠️ SUSPICIOUS EMAIL\n" + reasons +
               "\nRecommendation: Verify through official channels";
    } else if (isTrusted) {
        return "✅ TRUSTED EMAIL\n- No obvious signs of forgery";
    } else {
        return "⚠️ VALID BUT UNVERIFIED EMAIL\n- 🛑 Not in trusted domains list";
    }
}


    // ================= Helper Methods =================
    private JPanel createTipsPanel(String title, String tips) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder(title));
        JTextArea tipsArea = new JTextArea(tips);
        tipsArea.setEditable(false);
        tipsArea.setBackground(getBackground());
        tipsArea.setFont(new Font("SansSerif", Font.PLAIN, 12));
        panel.add(new JScrollPane(tipsArea), BorderLayout.CENTER);
        return panel;
    }

    private JButton createButton(String text, ActionListener action) {
        JButton btn = new JButton(text);
        btn.setBackground(BTN_COLOR);
        btn.setForeground(Color.WHITE);
        btn.setFocusPainted(false);
        btn.addActionListener(action);
        return btn;
    }

    private JTextArea createResultArea() {
        JTextArea area = new JTextArea();
        area.setEditable(false);
        area.setLineWrap(true);
        area.setWrapStyleWord(true);
        area.setFont(new Font("Monospaced", Font.PLAIN, 13));
        area.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
        return area;
    }

    private JPanel createInputPanel(String label, Component field, JButton btn) {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.add(new JLabel("Enter " + label + ":"), BorderLayout.NORTH);
        panel.add(field, BorderLayout.CENTER);
        panel.add(btn, BorderLayout.EAST);
        return panel;
    }

    private void displayResult(JTextArea area, String text, boolean isSafe) {
        area.setText(text);
        if (text.contains("🛑") || text.contains("HIGH-RISK")) {
            area.setForeground(WARNING_COLOR);
        } else if (text.contains("⚠️") || text.contains("SUSPICIOUS")) {
            area.setForeground(SUSPICIOUS_COLOR);
        } else if (text.contains("✅") || isSafe) {
            area.setForeground(SAFE_COLOR);
        } else {
            area.setForeground(Color.BLACK);
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            FakeDataDetector detector = new FakeDataDetector();
            detector.setVisible(true);
            
            JOptionPane.showMessageDialog(detector,
                "Advanced Fraud Detector\n\n" +
                "Detects:\n" +
                "- Phishing URLs\n" +
                "- Scam messages\n" +
                "- Fake contacts\n" +
                "- Fraudulent emails\n\n" +
                "Remember:\n" +
                "• No tool is 100% accurate\n" +
                "• Always verify through official channels",
                "Stay Safe Online", 
                JOptionPane.INFORMATION_MESSAGE);
        });
    }
}