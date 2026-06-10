import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { FaShieldAlt, FaSearch, FaCheckCircle, FaExclamationTriangle, FaBug } from 'react-icons/fa';
import { analyzeContent } from '../utils/mockDetection';
import './PhishingDetector.css';

const PhishingDetector = () => {
    const [input, setInput] = useState('');
    const [loading, setLoading] = useState(false);
    const [result, setResult] = useState(null);
    const [error, setError] = useState('');

    const handleAnalyze = async () => {
        if (!input.trim()) {
            setError('Please enter a URL or email content.');
            return;
        }
        setError('');
        setLoading(true);
        setResult(null);

        // Artificial delay for "scanning" effect
        await new Promise(resolve => setTimeout(resolve, 2000));

        try {
            const diagnosis = await analyzeContent(input);
            setResult(diagnosis);
        } catch (err) {
            setError('An error occurred during analysis. Please try again.');
        } finally {
            setLoading(false);
        }
    };

    const clearResult = () => {
        setResult(null);
        setInput('');
        setError('');
    };

    return (
        <div className="detector-container">
            <motion.div
                className="card neon-border"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.8 }}
            >
                <div className="header-icon">
                    <FaShieldAlt className="shield-icon" />
                </div>
                <h1 className="title glitch-text">NEURAL SHIELD</h1>
                <p className="subtitle">ML-Based Phishing Detection System</p>

                <div className="input-group">
                    <textarea
                        className="input-field terminal-input"
                        placeholder="> Enter suspicious URL or email content..."
                        value={input}
                        onChange={(e) => setInput(e.target.value)}
                        rows={5}
                        disabled={loading}
                    />
                    {error && <motion.p className="error-msg" initial={{ opacity: 0 }} animate={{ opacity: 1 }}>{error}</motion.p>}
                </div>

                <motion.button
                    className="analyze-btn"
                    onClick={handleAnalyze}
                    disabled={loading || !input.trim()}
                    whileHover={!loading ? { scale: 1.05, boxShadow: "0 0 15px var(--primary-color)" } : {}}
                    whileTap={!loading ? { scale: 0.95 } : {}}
                >
                    {loading ? (
                        <span className="scanning-text">
                            <FaSearch className="spin-icon" /> SCANNING...
                        </span>
                    ) : (
                        'INITIATE SCAN'
                    )}
                </motion.button>

                <AnimatePresence>
                    {loading && (
                        <motion.div
                            className="scanning-overlay"
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                        >
                            <div className="scanner-line"></div>
                            <p className="analyzing-text">ANALYZING THREAT VECTORS...</p>
                        </motion.div>
                    )}

                    {result && (
                        <motion.div
                            className={`result-card ${result.result.toLowerCase()}`}
                            initial={{ opacity: 0, scale: 0.9 }}
                            animate={{ opacity: 1, scale: 1 }}
                            exit={{ opacity: 0, scale: 0.9 }}
                            transition={{ type: "spring", stiffness: 200, damping: 20 }}
                        >
                            <div className="result-header">
                                <h2>
                                    {result.result === 'Safe' ? <FaCheckCircle /> : <FaExclamationTriangle />}
                                    {' ' + result.result.toUpperCase()}
                                </h2>
                                <span className="confidence">
                                    <FaBug className="bug-icon" /> {(result.confidence * 100).toFixed(1)}% PROBABILITY
                                </span>
                            </div>
                            <p className="result-details">{result.details}</p>
                            <button className="reset-btn" onClick={clearResult}>NEW SCAN</button>
                        </motion.div>
                    )}
                </AnimatePresence>
            </motion.div>
        </div>
    );
};

export default PhishingDetector;
