import React, { useState } from 'react';
import { Upload, Scan, FileText, ShieldAlert, CheckCircle, Image as ImageIcon, AlertCircle, Link2 } from 'lucide-react';
import { ocrApi } from '../services/ocrApi';
import { OCRAnalysisResponse } from '../types';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { Badge } from '../components/ui/Badge';
import { RiskScoreMeter } from '../components/analysis/RiskScoreMeter';
import { UrlAnalysisCard } from '../components/analysis/UrlAnalysisCard';

export const OcrScannerPage: React.FC = () => {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [previewUrl, setPreviewUrl] = useState<string | null>(null);
  const [result, setResult] = useState<OCRAnalysisResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      setSelectedFile(file);
      setPreviewUrl(URL.createObjectURL(file));
      setResult(null);
      setError(null);
    }
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      setSelectedFile(file);
      setPreviewUrl(URL.createObjectURL(file));
      setResult(null);
      setError(null);
    }
  };

  const handleUploadAndScan = async () => {
    if (!selectedFile) return;
    setLoading(true);
    setError(null);

    try {
      const data = await ocrApi.scanImage(selectedFile);
      setResult(data);
    } catch (err: any) {
      console.error('OCR Scan error:', err);
      setError(err.response?.data?.detail || err.message || 'Failed to extract text from screenshot.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-8">
      {/* Page Banner */}
      <div className="glass-panel p-6 rounded-2xl border border-cyan-500/20 glow-cyan flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center space-x-2">
            <Scan className="w-5 h-5 text-cyan-400" />
            <h2 className="text-2xl font-black text-white">OCR Screenshot Threat Scanner</h2>
          </div>
          <p className="text-xs text-slate-400">
            Upload email or SMS screenshots (.png, .jpg, .webp) for AI text extraction, phishing analysis, and 6-vector URL scanning.
          </p>
        </div>
      </div>

      {/* Upload Zone & Image Preview Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Dropzone Container */}
        <Card className="p-6 space-y-4">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <Upload className="w-4 h-4 text-blue-400" /> Upload Screenshot Image
          </h3>

          <div
            onDragOver={(e) => e.preventDefault()}
            onDrop={handleDrop}
            className="border-2 border-dashed border-slate-700 hover:border-blue-500/50 bg-slate-950/60 rounded-2xl p-8 text-center transition-all duration-200 cursor-pointer space-y-4"
          >
            <input
              type="file"
              accept="image/*"
              onChange={handleFileChange}
              className="hidden"
              id="screenshot-upload-input"
            />
            <label htmlFor="screenshot-upload-input" className="cursor-pointer block space-y-3">
              <div className="w-12 h-12 rounded-2xl bg-blue-600/10 border border-blue-500/30 text-blue-400 mx-auto flex items-center justify-center">
                <ImageIcon className="w-6 h-6" />
              </div>
              <div className="space-y-1">
                <p className="text-sm font-semibold text-slate-200">
                  {selectedFile ? selectedFile.name : 'Drag & drop image file or click to browse'}
                </p>
                <p className="text-xs text-slate-500 font-mono">Supports PNG, JPG, JPEG, WEBP (Max 10MB)</p>
              </div>
            </label>
          </div>

          <Button
            variant="primary"
            className="w-full font-mono text-xs uppercase"
            disabled={!selectedFile || loading}
            isLoading={loading}
            onClick={handleUploadAndScan}
          >
            <Scan className="w-4 h-4 mr-2" /> Extract Text & Scan Screenshot
          </Button>

          {error && <p className="text-xs text-rose-400 font-mono text-center">{error}</p>}
        </Card>

        {/* Original Image Preview Box */}
        <Card className="p-6 space-y-4 flex flex-col justify-between">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <ImageIcon className="w-4 h-4 text-cyan-400" /> Original Screenshot Preview
          </h3>

          {previewUrl ? (
            <div className="rounded-xl overflow-hidden border border-slate-800 bg-slate-950/80 max-h-72 flex items-center justify-center p-2">
              <img src={previewUrl} alt="Screenshot Preview" className="max-h-64 object-contain rounded" />
            </div>
          ) : (
            <div className="h-64 rounded-xl border border-slate-800/80 bg-slate-950/40 flex flex-col items-center justify-center text-slate-600 space-y-2">
              <ImageIcon className="w-10 h-10 stroke-1" />
              <p className="text-xs font-mono">No image selected for preview</p>
            </div>
          )}
        </Card>
      </div>

      {/* Analysis Results Display */}
      {result && (
        <div className="space-y-6 animate-in fade-in duration-300">
          {/* Top Diagnostics Dashboard Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 p-6 rounded-2xl bg-slate-900/60 border border-slate-800">
            {/* Risk Gauge */}
            <div className="flex flex-col items-center justify-center border-b md:border-b-0 md:border-r border-slate-800 pb-4 md:pb-0 md:pr-4">
              <RiskScoreMeter score={result.risk_score} size="md" />
              <div className="mt-3 text-center">
                <span className="text-[11px] font-mono text-slate-400">AI Confidence Level</span>
                <p className="text-sm font-bold text-cyan-400 font-mono">{(result.confidence * 100).toFixed(0)}% Certainty</p>
              </div>
            </div>

            {/* Category Spectrum */}
            <div className="col-span-2 space-y-2.5 font-mono text-xs">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">Threat Category Spectrum</h4>
                <Badge variant={result.risk_score >= 60 ? 'danger' : result.risk_score >= 30 ? 'warning' : 'success'}>
                  {result.threat_type}
                </Badge>
              </div>

              <div>
                <div className="flex justify-between text-[11px] mb-1">
                  <span className="text-slate-400">Phishing Indicator</span>
                  <span className="text-rose-400 font-bold">{result.breakdown.phishing_score}%</span>
                </div>
                <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                  <div className="h-full bg-rose-500 rounded-full" style={{ width: `${result.breakdown.phishing_score}%` }}></div>
                </div>
              </div>

              <div>
                <div className="flex justify-between text-[11px] mb-1">
                  <span className="text-slate-400">Scam & Fraud Score</span>
                  <span className="text-amber-400 font-bold">{result.breakdown.scam_score}%</span>
                </div>
                <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                  <div className="h-full bg-amber-500 rounded-full" style={{ width: `${result.breakdown.scam_score}%` }}></div>
                </div>
              </div>

              <div>
                <div className="flex justify-between text-[11px] mb-1">
                  <span className="text-slate-400">Suspicious URL Risk</span>
                  <span className="text-cyan-400 font-bold">{result.breakdown.url_score}%</span>
                </div>
                <div className="h-1.5 w-full bg-slate-800 rounded-full overflow-hidden">
                  <div className="h-full bg-cyan-500 rounded-full" style={{ width: `${result.breakdown.url_score}%` }}></div>
                </div>
              </div>
            </div>
          </div>

          {/* Extracted Text Box */}
          <Card className="p-6 space-y-3">
            <h3 className="text-sm font-bold text-white flex items-center gap-2">
              <FileText className="w-4 h-4 text-blue-400" /> Extracted OCR Text Content
            </h3>
            <div className="p-4 rounded-xl bg-slate-950/90 border border-slate-800 text-slate-200 font-mono text-xs leading-relaxed whitespace-pre-wrap select-text">
              {result.extracted_text || 'No text recognized.'}
            </div>
          </Card>

          {/* Extracted URLs 6-Vector Threat Matrix */}
          {result.extracted_urls.length > 0 && (
            <div className="space-y-3">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Link2 className="w-4 h-4 text-cyan-400" /> Extracted URLs 6-Vector Threat Analysis ({result.extracted_urls.length})
              </h3>
              <div className="space-y-3">
                {result.extracted_urls.map((link, i) => (
                  <UrlAnalysisCard key={i} url={link} />
                ))}
              </div>
            </div>
          )}

          {/* Evidentiary Reasons & Recommendations */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Card className="p-6 space-y-3">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <ShieldAlert className="w-4 h-4 text-amber-400" /> AI Evidentiary Reasons
              </h3>
              <div className="space-y-2">
                {result.reasons.map((reason, idx) => (
                  <div key={idx} className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 text-xs text-slate-300 flex items-start space-x-2.5">
                    <AlertCircle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                    <span>{reason}</span>
                  </div>
                ))}
              </div>
            </Card>

            <Card className="p-6 space-y-3">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-emerald-400" /> Actionable Recommendations
              </h3>
              <div className="space-y-2">
                {result.recommendations.map((rec, idx) => (
                  <div key={idx} className="p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-xs text-emerald-300 flex items-start space-x-2.5">
                    <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    <span>{rec}</span>
                  </div>
                ))}
              </div>
            </Card>
          </div>
        </div>
      )}
    </div>
  );
};
