"use client";

import { useState } from "react";
import Image from "next/image";
import { FileDown, Link, Loader2 } from "lucide-react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { jsPDF } from "jspdf";
import Papa from "papaparse";
import { Progress } from "@/components/ui/progress";

interface PhishingResponse {
  prediction: string;
  [key: string]: string | number;
}

interface BulkAnalysisResult {
  url: string;
  prediction: string;
  features?: Record<string, string | number>;
}

export default function Home() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<PhishingResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [bulkResults, setBulkResults] = useState<BulkAnalysisResult[]>([]);
  const [bulkProgress, setBulkProgress] = useState(0);
  const [isBulkAnalyzing, setIsBulkAnalyzing] = useState(false);

  const generatePDF = (data: PhishingResponse | BulkAnalysisResult) => {
    const pdf = new jsPDF();
    const pageWidth = pdf.internal.pageSize.getWidth();
    
    // Header
    pdf.setFontSize(20);
    pdf.text("Phishing Detection Report", pageWidth / 2, 20, { align: "center" });
    
    // URL
    pdf.setFontSize(12);
    pdf.text(`URL: ${url}`, 20, 40);
    
    // Prediction Result
    pdf.setFontSize(16);
    const predictionText = `Prediction: ${data.prediction === "bad" ? "Potential Phishing Website" : "Safe Website"}`;
    pdf.text(predictionText, 20, 60);
    
    // Features
    pdf.setFontSize(14);
    pdf.text("Feature Analysis:", 20, 80);
    
    let yPos = 90;
    Object.entries(data)
      .filter(([key]) => key !== "prediction")
      .forEach(([key, value]) => {
        if (yPos > 250) {
          pdf.addPage();
          yPos = 20;
        }
        pdf.setFontSize(12);
        pdf.text(`${key}: ${value}`, 20, yPos);
        yPos += 10;
      });
    
    // Save the PDF
    pdf.save(`phishing-report-${new Date().getTime()}.pdf`);
  };

  const handleUrlSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    try {
      const response = await fetch("http://localhost:8000/api/check-phishing", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const data: PhishingResponse = await response.json();
      setResult(data);
    } catch (error) {
      console.error("Error:", error);
    } finally {
      setIsLoading(false);
    }
  };

  const handleBulkAnalysis = async (file: File) => {
    setIsBulkAnalyzing(true);
    setBulkResults([]);
    setBulkProgress(0);

    Papa.parse(file, {
      complete: async (results) => {
        const urls = results.data.flat().filter(Boolean);
        const totalUrls = urls.length;
        const analysisResults: BulkAnalysisResult[] = [];

        for (let i = 0; i < urls.length; i++) {
          try {
            const response = await fetch("http://localhost:8000/api/check-phishing", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ url: urls[i] }),
            });
            const data = await response.json();
            analysisResults.push({
              url: urls[i] as string,
              prediction: data.prediction,
              features: data,
            });
          } catch (error) {
            console.error(`Error analyzing ${urls[i]}:`, error);
          }
          setBulkProgress(((i + 1) / totalUrls) * 100);
        }

        setBulkResults(analysisResults);
        setIsBulkAnalyzing(false);
      },
      error: (error) => {
        console.error("Error parsing CSV:", error);
        setIsBulkAnalyzing(false);
      },
    });
  };

  const downloadBulkReport = () => {
    const pdf = new jsPDF();
    const pageWidth = pdf.internal.pageSize.getWidth();
    
    pdf.setFontSize(20);
    pdf.text("Bulk Analysis Report", pageWidth / 2, 20, { align: "center" });
    
    let yPos = 40;
    bulkResults.forEach((result, index) => {
      if (yPos > 250) {
        pdf.addPage();
        yPos = 20;
      }
      
      pdf.setFontSize(14);
      pdf.text(`URL ${index + 1}: ${result.url}`, 20, yPos);
      yPos += 10;
      
      pdf.setFontSize(12);
      pdf.text(`Prediction: ${result.prediction === "bad" ? "Potential Phishing" : "Safe"}`, 30, yPos);
      yPos += 20;
    });
    
    pdf.save(`bulk-analysis-report-${new Date().getTime()}.pdf`);
  };

  return (
    <div className="min-h-screen bg-gradient-to-b from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800">
      {/* Header */}
      <header className="border-b bg-white dark:bg-gray-950 shadow-sm">
        <div className="container mx-auto px-4 py-4 flex items-center">
          <Image
            src="/nitk.png"
            alt="NITK Logo"
            width={40}
            height={40}
            className="h-10 w-10 mr-4"
          />
          <div>
            <h1 className="text-xl font-bold text-gray-900 dark:text-gray-100">
              National Institute of Technology Karnataka, Surathkal
            </h1>
            <h2 className="text-sm text-gray-600 dark:text-gray-400">
              Department of Information Technology
            </h2>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-8">
        <Card className="mb-8">
          <CardHeader>
            <CardTitle>
              Phishing Website Detection System [ IT352 Course Project ]
            </CardTitle>
            <CardDescription>
              Analyze URLs to detect potential phishing websites using advanced
              machine learning algorithms
            </CardDescription>
          </CardHeader>
        </Card>

        <Tabs defaultValue="single" className="space-y-4">
          <TabsList>
            <TabsTrigger value="single">Single URL Analysis</TabsTrigger>
            <TabsTrigger value="bulk">Bulk Analysis</TabsTrigger>
          </TabsList>

          <TabsContent value="single">
            <Card>
              <CardHeader>
                <CardTitle>Analyze Single URL</CardTitle>
                <CardDescription>
                  Enter a URL to analyze its potential for being a phishing
                  website
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <form onSubmit={handleUrlSubmit} className="flex space-x-2">
                  <Input
                    placeholder="Enter URL to analyze..."
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                  />
                  <Button type="submit" disabled={isLoading}>
                    {isLoading ? (
                      <>
                        <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                        Analyzing...
                      </>
                    ) : (
                      <>
                        <Link className="mr-2 h-4 w-4" />
                        Analyze
                      </>
                    )}
                  </Button>
                </form>

                {result && (
                  <div className="mt-6 space-y-4">
                    <div
                      className={`p-4 rounded-lg ${
                        result.prediction === "bad"
                          ? "bg-red-100 text-red-700 dark:bg-red-900/20 dark:text-red-400"
                          : "bg-green-100 text-green-700 dark:bg-green-900/20 dark:text-green-400"
                      }`}
                    >
                      <h3 className="font-semibold">
                        {result.prediction === "bad"
                          ? "Potential Phishing Website Detected!"
                          : "Website Appears Safe"}
                      </h3>
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                      {Object.entries(result)
                        .filter(([key]) => key !== "prediction")
                        .map(([key, value]) => (
                          <div
                            key={key}
                            className="p-4 bg-white dark:bg-gray-800 rounded-lg shadow-sm"
                          >
                            <div className="text-sm text-gray-500 dark:text-gray-400">
                              {key}
                            </div>
                            <div className="font-medium">{value.toString()}</div>
                          </div>
                        ))}
                    </div>

                    <Button onClick={() => generatePDF(result)}>
                      <FileDown className="mr-2 h-4 w-4" />
                      Download Report
                    </Button>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="bulk">
            <Card>
              <CardHeader>
                <CardTitle>Bulk URL Analysis</CardTitle>
                <CardDescription>
                  Upload a CSV file containing URLs for batch analysis
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div>
                  <Label htmlFor="file" className="block mb-2">
                    Upload CSV File
                  </Label>
                  <Input
                    id="file"
                    type="file"
                    accept=".csv"
                    onChange={(e) => {
                      const file = e.target.files?.[0];
                      if (file) handleBulkAnalysis(file);
                    }}
                    disabled={isBulkAnalyzing}
                  />
                </div>

                {isBulkAnalyzing && (
                  <div className="space-y-2">
                    <Progress value={bulkProgress} />
                    <p className="text-sm text-gray-500">
                      Analyzing URLs... {Math.round(bulkProgress)}%
                    </p>
                  </div>
                )}

                {bulkResults.length > 0 && (
                  <div className="space-y-4">
                    <div className="rounded-lg border p-4">
                      <h3 className="font-semibold mb-2">Analysis Results</h3>
                      <div className="space-y-2">
                        {bulkResults.map((result, index) => (
                          <div
                            key={index}
                            className={`p-3 rounded-md ${
                              result.prediction === "bad"
                                ? "bg-red-50 dark:bg-red-900/10"
                                : "bg-green-50 dark:bg-green-900/10"
                            }`}
                          >
                            <p className="text-sm font-medium truncate">
                              {result.url}
                            </p>
                            <p
                              className={`text-sm ${
                                result.prediction === "bad"
                                  ? "text-red-600 dark:text-red-400"
                                  : "text-green-600 dark:text-green-400"
                              }`}
                            >
                              {result.prediction === "bad"
                                ? "Potential Phishing"
                                : "Safe"}
                            </p>
                          </div>
                        ))}
                      </div>
                    </div>

                    <Button onClick={downloadBulkReport}>
                      <FileDown className="mr-2 h-4 w-4" />
                      Download Bulk Report
                    </Button>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </main>

      {/* Footer */}
      <footer className="border-t bg-white dark:bg-gray-950 mt-8">
        <div className="container mx-auto px-4 py-6">
          <div className="container mx-auto text-center text-gray-700 dark:text-gray-300 text-sm">
            <p className="font-medium">
              Developed by
              <span className="font-semibold text-gray-900 dark:text-gray-100">
                {" "}
                Nithin S{" "}
              </span>{" "}
              [221IT085] &
              <span className="font-semibold text-gray-900 dark:text-gray-100">
                {" "}
                Jay Chavan{" "}
              </span>{" "}
              [221IT020]
            </p>
            <p className="mt-1">
              © {new Date().getFullYear()} National Institute of Technology
              Karnataka, Surathkal
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}