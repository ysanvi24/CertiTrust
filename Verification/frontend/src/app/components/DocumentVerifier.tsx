import React, { useState, useCallback, useEffect } from "react";
import { useDropzone } from "react-dropzone";
import { motion, AnimatePresence } from "motion/react";
import { 
  UploadCloud, 
  FileText, 
  ShieldCheck, 
  ShieldAlert, 
  Check, 
  X, 
  ScanLine, 
  Activity, 
  Search, 
  FileCheck, 
  ArrowRight,
  RefreshCw,
  Lock,
  Download
} from "lucide-react";
import { cn } from "../../lib/utils";
import { projectId, publicAnonKey } from "/utils/supabase/info";
import axios from "axios";

type VerificationStatus = "idle" | "uploading" | "scanning" | "analyzing" | "complete" | "error";

interface VerificationResult {
  score: number;
  verdict: "Real" | "Fake" | "Tampered";
  details: string;
  id?: string;
  timestamp?: string;
  qr_verified?: boolean;
  ai_check?: {
    ai_manipulation_likely: boolean;
    trust_score: number;
  };
}

export function DocumentVerifier() {
  const [status, setStatus] = useState<VerificationStatus>("idle");
  const [file, setFile] = useState<File | null>(null);
  const [progress, setProgress] = useState(0);
  const [scanStep, setScanStep] = useState(0);
  const [result, setResult] = useState<VerificationResult | null>(null);
  const [errorMessage, setErrorMessage] = useState("");

  // Scan steps for the "Analyzing" phase visual
  const scanSteps = [
    "Initiating secure handshake...",
    "Hashing file contents...",
    "Verifying metadata integrity...",
    "Analyzing compression artifacts...",
    "Cross-referencing global database...",
    "Finalizing trust score..."
  ];

  const onDrop = useCallback(async (acceptedFiles: File[]) => {
    if (acceptedFiles.length > 0) {
      const selectedFile = acceptedFiles[0];
      setFile(selectedFile);
      setStatus("scanning");
      setProgress(0);
      setScanStep(0);
      setErrorMessage("");
      verifyDocument(selectedFile);
    }
  }, []);

  const verifyDocument = async (fileToVerify: File) => {
    try {
      setStatus("uploading");

      const formData = new FormData();
      formData.append("file", fileToVerify);

      // Make API call to the backend
      const response = await axios.post("http://localhost:8000/verify-document", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });

      const { data } = response;

      if (data.status === "verified") {
        setResult(data); // Store the verification result
        setStatus("complete");
      } else {
        setErrorMessage("Document verification failed.");
        setStatus("error");
      }
    } catch (err) {
      console.error(err);
      setErrorMessage("An error occurred during verification.");
      setStatus("error");
    }
  };

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'application/pdf': ['.pdf'],
      'image/*': ['.png', '.jpg', '.jpeg', '.webp'],
      'application/msword': ['.doc', '.docx'],
    },
    maxFiles: 1,
    multiple: false
  });

  const resetVerification = () => {
    setStatus("idle");
    setFile(null);
    setResult(null);
    setProgress(0);
    setScanStep(0);
    setErrorMessage("");
  };

  const getStatusColor = (score: number) => {
    if (score >= 85) return "text-emerald-600 bg-emerald-50 border-emerald-200";
    if (score >= 50) return "text-amber-600 bg-amber-50 border-amber-200";
    return "text-rose-600 bg-rose-50 border-rose-200";
  };

  return (
    <div className="w-full max-w-3xl mx-auto px-4 py-12 font-sans">
      
      {/* Brand Header */}
      <div className="flex items-center justify-center mb-12 space-x-3">
        <div className="w-10 h-10 bg-slate-900 rounded-lg flex items-center justify-center text-white shadow-lg">
          <ShieldCheck className="w-6 h-6" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-slate-900 tracking-tight">VeriTrust<span className="text-slate-400 font-light">Platform</span></h1>
          <div className="flex items-center space-x-2 text-xs text-slate-500 font-medium tracking-wide uppercase">
            <Lock className="w-3 h-3" />
            <span>Secure Verification Environment</span>
          </div>
        </div>
      </div>

      <div className="bg-white rounded-2xl shadow-xl border border-slate-100 overflow-hidden relative min-h-[500px] flex flex-col">
        
        {/* Top Bar Decoration */}
        <div className="h-1.5 w-full bg-gradient-to-r from-slate-800 via-indigo-600 to-slate-800" />

        <div className="flex-1 flex flex-col p-8 md:p-12 relative">
          <AnimatePresence mode="wait">
            
            {/* IDLE STATE */}
            {(status === "idle" || status === "error") && (
              <motion.div
                key="idle"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="flex-1 flex flex-col items-center justify-center"
              >
                {status === "error" && (
                  <div className="w-full mb-6 p-4 bg-rose-50 text-rose-700 rounded-lg text-sm flex items-center justify-center border border-rose-100">
                    <ShieldAlert className="w-4 h-4 mr-2" />
                    {errorMessage}
                  </div>
                )}

                <div 
                  {...getRootProps()}
                  className={cn(
                    "w-full max-w-lg aspect-[1.6] border-2 border-dashed rounded-xl flex flex-col items-center justify-center transition-all duration-300 cursor-pointer relative overflow-hidden group",
                    isDragActive 
                      ? "border-indigo-500 bg-indigo-50/50" 
                      : "border-slate-200 hover:border-slate-400 hover:bg-slate-50/50"
                  )}
                >
                  <input {...getInputProps()} />
                  
                  {/* Background Pattern */}
                  <div className="absolute inset-0 opacity-[0.03] pointer-events-none" 
                       style={{ backgroundImage: 'radial-gradient(circle at 2px 2px, black 1px, transparent 0)', backgroundSize: '24px 24px' }} 
                  />

                  <div className="w-16 h-16 bg-slate-100 rounded-2xl flex items-center justify-center mb-6 shadow-sm group-hover:scale-105 transition-transform duration-300">
                    <UploadCloud className="w-8 h-8 text-slate-600" />
                  </div>
                  
                  <h3 className="text-xl font-semibold text-slate-900 mb-2">Upload Document</h3>
                  <p className="text-slate-500 text-center max-w-xs mb-8 text-sm leading-relaxed">
                    Drag & drop your PDF, JPG, or DOCX file here to begin the authenticity verification process.
                  </p>
                  
                  <button className="px-6 py-2.5 bg-slate-900 hover:bg-slate-800 text-white text-sm font-medium rounded-lg shadow-sm transition-all flex items-center gap-2">
                    <Search className="w-4 h-4" />
                    Browse Files
                  </button>
                </div>
                
                <p className="mt-8 text-xs text-slate-400 font-medium text-center uppercase tracking-widest">
                  AES-256 Encrypted • Zero-Knowledge Analysis
                </p>
              </motion.div>
            )}

            {/* SCANNING STATE */}
            {status === "scanning" && (
              <motion.div
                key="scanning"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="flex-1 flex flex-col items-center justify-center w-full max-w-lg mx-auto"
              >
                <div className="relative w-full mb-12">
                   {/* File Card */}
                   <div className="bg-white border border-slate-200 shadow-xl rounded-xl p-6 mx-auto w-64 relative z-10 overflow-hidden">
                      <div className="flex items-center gap-3 mb-4 border-b border-slate-100 pb-4">
                        <FileText className="w-8 h-8 text-indigo-600" />
                        <div className="overflow-hidden">
                          <div className="text-sm font-semibold text-slate-900 truncate">{file?.name}</div>
                          <div className="text-xs text-slate-500">{(file?.size ? file.size / 1024 : 0).toFixed(1)} KB</div>
                        </div>
                      </div>
                      <div className="space-y-2">
                         <div className="h-2 bg-slate-100 rounded w-3/4" />
                         <div className="h-2 bg-slate-100 rounded w-full" />
                         <div className="h-2 bg-slate-100 rounded w-5/6" />
                      </div>

                      {/* Scanning Line */}
                      <motion.div 
                        className="absolute inset-0 bg-gradient-to-b from-transparent via-indigo-500/10 to-transparent h-[40%] w-full pointer-events-none border-b-2 border-indigo-500/30"
                        animate={{ top: ["-40%", "140%"] }}
                        transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
                      />
                   </div>

                   {/* Background Glow */}
                   <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-64 h-64 bg-indigo-500/5 blur-3xl rounded-full -z-10" />
                </div>

                <div className="w-full space-y-4">
                  <div className="flex justify-between text-xs font-semibold uppercase tracking-wider text-slate-500 mb-1">
                    <span>Analysis in Progress</span>
                    <span>{Math.round(progress)}%</span>
                  </div>
                  <div className="w-full h-1.5 bg-slate-100 rounded-full overflow-hidden">
                    <motion.div 
                      className="h-full bg-slate-900 rounded-full"
                      initial={{ width: 0 }}
                      animate={{ width: `${progress}%` }}
                      transition={{ ease: "linear" }}
                    />
                  </div>
                  
                  <div className="h-6 overflow-hidden relative">
                    <AnimatePresence mode="wait">
                       <motion.p
                         key={scanStep}
                         initial={{ y: 20, opacity: 0 }}
                         animate={{ y: 0, opacity: 1 }}
                         exit={{ y: -20, opacity: 0 }}
                         className="text-sm text-slate-600 font-mono text-center absolute w-full"
                       >
                         {">"} {scanSteps[scanStep]}
                       </motion.p>
                    </AnimatePresence>
                  </div>
                </div>
              </motion.div>
            )}

            {/* COMPLETE STATE */}
            {status === "complete" && result && (
              <motion.div
                key="complete"
                initial={{ opacity: 0, scale: 0.98 }}
                animate={{ opacity: 1, scale: 1 }}
                className="flex-1 flex flex-col w-full h-full"
              >
                <div className="flex items-center justify-between mb-8 pb-6 border-b border-slate-100">
                  <div>
                    <h2 className="text-xl font-bold text-slate-900">Verification Report</h2>
                    <p className="text-sm text-slate-500">ID: {result.id?.slice(0, 18) || "REF-88392-X"}...</p>
                  </div>
                  <div className="text-right">
                     <div className="text-xs text-slate-400 uppercase tracking-wider mb-1">Timestamp</div>
                     <div className="text-sm font-mono text-slate-600">
                        {new Date().toLocaleTimeString()} UTC
                     </div>
                  </div>
                </div>

                <div className="flex-1 grid grid-cols-1 md:grid-cols-12 gap-8">
                  {/* Score Column */}
                  <div className="md:col-span-5 flex flex-col items-center justify-center p-6 bg-slate-50 rounded-xl border border-slate-100">
                     <div className="relative w-40 h-40 flex items-center justify-center mb-6">
                        <svg className="w-full h-full transform -rotate-90">
                           <circle cx="80" cy="80" r="70" stroke="currentColor" strokeWidth="8" fill="transparent" className="text-slate-200" />
                           <motion.circle 
                              cx="80" cy="80" r="70" 
                              stroke="currentColor" strokeWidth="8" 
                              fill="transparent" 
                              strokeDasharray={440}
                              strokeDashoffset={440 - (440 * (result.ai_check?.trust_score ?? 0)) / 100}
                              className={cn(
                                "transition-all duration-1000 ease-out",
                                (result.ai_check?.trust_score ?? 0) >= 85 ? "text-emerald-500" : ((result.ai_check?.trust_score ?? 0) >= 50 ? "text-amber-500" : "text-rose-500")
                              )}
                              strokeLinecap="round"
                              initial={{ strokeDashoffset: 440 }}
                              animate={{ strokeDashoffset: 440 - (440 * (result.ai_check?.trust_score ?? 0)) / 100 }}
                           />
                        </svg>
                        <div className="absolute flex flex-col items-center">
                          <span className="text-4xl font-bold text-slate-900">{result.ai_check?.trust_score}%</span>
                          <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">Trust Score</span>
                        </div>
                     </div>
                     
                     <div className={cn(
                       "px-4 py-1.5 rounded-full text-sm font-bold uppercase tracking-wider flex items-center gap-2 mb-2",
                       getStatusColor(result.score)
                     )}>
                        {result.verdict === "Real" ? <Check className="w-4 h-4" /> : <ShieldAlert className="w-4 h-4" />}
                        {result.verdict}
                     </div>
                  </div>

                  {/* Details Column */}
                  <div className="md:col-span-7 space-y-6">

                    <div className="space-y-3">
                       <h3 className="text-sm font-semibold text-slate-900 uppercase tracking-wide mb-3 flex items-center gap-2">
                         <FileCheck className="w-4 h-4 text-slate-400" /> Integrity Checks
                       </h3>
                       
                       <div className="grid grid-cols-1 gap-2">
                          {[
                            { label: "Signature Consistency", status: result.qr_verified },
                            { label: "AI Analysis", status: !(result.ai_check?.ai_manipulation_likely) },
                          ].map((item, i) => (
                            <div key={i} className="flex items-center justify-between p-2.5 bg-slate-50 rounded border border-slate-100">
                               <span className="text-sm text-slate-600">{item.label}</span>
                               {item.status ? (
                                 <span className="flex items-center text-xs font-medium text-emerald-600 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-100">
                                   <Check className="w-3 h-3 mr-1" /> PASS
                                 </span>
                               ) : (
                                 <span className="flex items-center text-xs font-medium text-rose-600 bg-rose-50 px-2 py-0.5 rounded border border-rose-100">
                                   <X className="w-3 h-3 mr-1" /> FLAG
                                 </span>
                               )}
                            </div>
                          ))}
                       </div>
                    </div>
                  </div>
                </div>

                <div className="mt-8 pt-6 border-t border-slate-100 flex items-center justify-between">
                   <button 
                     onClick={resetVerification}
                     className="text-slate-500 hover:text-slate-800 text-sm font-medium flex items-center gap-2 transition-colors"
                   >
                     <RefreshCw className="w-4 h-4" />
                     Verify New Document
                   </button>
                </div>
              </motion.div>
            )}

          </AnimatePresence>
        </div>
      </div>
      
      <div className="text-center mt-8">
         <p className="text-slate-400 text-xs">
           © 2026 VeriTrust Systems Inc. All rights reserved. <br/>
           Authorized use only. IP logged for security purposes.
         </p>
      </div>
    </div>
  );
}
