
/**
 * Mock function to simulate phishing detection.
 * In a real application, this would call an API with the ML model.
 * 
 * @param {string} input - The URL or text content to analyze.
 * @returns {Promise<{result: 'Phishing' | 'Safe', confidence: number, details: string}>}
 */
export const analyzeContent = async (input) => {
    return new Promise((resolve) => {
        setTimeout(() => {
            const lowerInput = input.toLowerCase();

            // Simple keyword-based logic for demonstration
            const suspiciousKeywords = [
                'login', 'verify', 'account', 'banking', 'secure-update',
                'paypal-support', 'apple-id', 'urgent', 'suspend', 'confirm'
            ];

            const safeKeywords = [
                'google.com', 'microsoft.com', 'github.com', 'stackoverflow.com',
                'example.com', 'mysite.com'
            ];

            // Check for known safe domains first
            if (safeKeywords.some(keyword => lowerInput.includes(keyword))) {
                resolve({
                    result: 'Safe',
                    confidence: 0.95 + Math.random() * 0.04,
                    details: 'Domain is recognized as a trusted entity.'
                });
                return;
            }

            // Check for suspicious patterns
            const isSuspicious = suspiciousKeywords.some(keyword => lowerInput.includes(keyword));

            if (isSuspicious) {
                resolve({
                    result: 'Phishing',
                    confidence: 0.85 + Math.random() * 0.1,
                    details: 'Detected suspicious keywords often associated with phishing attempts.'
                });
            } else {
                // Default to Safe but with lower confidence for unknown inputs in this prototype
                // Or randomly flag some as suspicious for demo purposes if they are long/complex
                if (input.length > 50 && Math.random() > 0.7) {
                    resolve({
                        result: 'Phishing',
                        confidence: 0.70,
                        details: 'Unusual URL structure detected.'
                    });
                } else {
                    resolve({
                        result: 'Safe',
                        confidence: 0.90,
                        details: 'No immediate threats detected.'
                    });
                }
            }
        }, 1500); // Simulate network/processing delay
    });
};
