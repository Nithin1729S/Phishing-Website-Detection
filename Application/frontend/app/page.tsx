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

  // Helper function to convert an image URL to a Base64 string
const loadImageAsBase64 = async (url: string): Promise<string> => {
  const response = await fetch(url);
  const blob = await response.blob();
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onloadend = () => resolve(reader.result as string);
    reader.onerror = reject;
    reader.readAsDataURL(blob);
  });
};

const generatePDF = async (data: PhishingResponse | BulkAnalysisResult, urlToAnalyze: string) => {
  const pdf = new jsPDF();
  const pageWidth = pdf.internal.pageSize.getWidth();
  const pageHeight = pdf.internal.pageSize.getHeight();

  // Add a colored header background
  pdf.setFillColor(240, 240, 240);
  pdf.rect(0, 0, pageWidth, 50, 'F');

  // Load the NITK logo from the public folder (make sure nitk.png is in the public folder)
  const logoUrl = '/nitk.png';
  const logoBase64 = await loadImageAsBase64(logoUrl);
  pdf.addImage(logoBase64, 'PNG', 15, 10, 30, 30);

  // Add title lines
  pdf.setFontSize(16);
  pdf.setTextColor(44, 62, 80);
  pdf.text("National Institute of Technology Karnataka, Surathkal", pageWidth / 2 + 10, 20, { align: "center" });
  
  pdf.setFontSize(14);
  pdf.setTextColor(100, 100, 100);
  pdf.text("Department of Information Technology", pageWidth / 2 + 10, 35, { align: "center" });
  
  // Phishing Detection Report title
  pdf.setFontSize(24);
  pdf.setTextColor(44, 62, 80);
  pdf.text("Phishing Detection Report", pageWidth / 2, 60, { align: "center" });
  
  // Divider line
  pdf.setDrawColor(52, 152, 219);
  pdf.setLineWidth(0.5);
  pdf.line(20, 70, pageWidth - 20, 70);
  
  // URL section with box
  pdf.setFillColor(249, 249, 249);
  pdf.rect(20, 80, pageWidth - 40, 20, 'F');
  pdf.setFontSize(12);
  pdf.setTextColor(44, 62, 80);
  pdf.text("URL:", 25, 90);
  pdf.setTextColor(52, 152, 219);
  pdf.text(urlToAnalyze, 45, 90);
  
  // Prediction Result with colored box
  const isPotentialPhishing = data.prediction === "bad";
  if (isPotentialPhishing) {
    pdf.setFillColor(255, 240, 240);
  } else {
    pdf.setFillColor(240, 255, 240);
  }
  pdf.rect(20, 110, pageWidth - 40, 25, 'F');
  pdf.setFontSize(16);
  const textColor = isPotentialPhishing ? [192, 57, 43] : [39, 174, 96];
  pdf.setTextColor(textColor[0], textColor[1], textColor[2]);
  pdf.text(
    `Prediction: ${isPotentialPhishing ? "Potential Phishing Website" : "Safe Website"}`,
    pageWidth / 2,
    125,
    { align: "center" }
  );
  
  // Features section
  pdf.setFontSize(18);
  pdf.setTextColor(44, 62, 80);
  pdf.text("Feature Analysis", pageWidth / 2, 150, { align: "center" });
  
  // Feature grid
  let yPos = 165;
  let xPos = 20;
  const features = Object.entries(data).filter(([key]) => key !== "prediction");
  
  features.forEach(([key, value], index) => {
    if (yPos > pageHeight - 20) {
      pdf.addPage();
      yPos = 20;
    }
    
    // Feature box
    pdf.setFillColor(249, 249, 249);
    pdf.rect(xPos, yPos, (pageWidth - 50) / 2, 25, 'F');
    
    // Feature name
    pdf.setFontSize(11);
    pdf.setTextColor(52, 73, 94);
    pdf.text(key, xPos + 5, yPos + 10);
    
    // Feature value
    pdf.setFontSize(12);
    pdf.setTextColor(44, 62, 80);
    pdf.text(value.toString(), xPos + 5, yPos + 20);
    
    // Adjust position for next feature
    if (index % 2 === 0) {
      xPos = pageWidth / 2 + 10;
    } else {
      xPos = 20;
      yPos += 35;
    }
  });
  
  // Footer
  const timestamp = new Date().toLocaleString();
  pdf.setFontSize(10);
  pdf.setTextColor(128, 128, 128);
  pdf.text(`Generated on: ${timestamp}`, 20, pageHeight - 10);
  
  // Save the PDF
  pdf.save(`${urlToAnalyze}-phishing-report-${timestamp}.pdf`);
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
              Phishing Website Detection System [ IT352 Course Project Jan - May 2025 ]
            </CardTitle>
            <CardDescription>
            Developed by
              <span className="font-semibold text-gray-900 dark:text-gray-100">
                {" "}
                Nithin S{" "}
              </span>{" "}
              [221IT085] 
              &
              <span className="font-semibold text-gray-900 dark:text-gray-100">
                {" "}
                Jay Chavan {" "}
              </span>{" "}
              [221IT020] 
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
                    required
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
                    <Button onClick={() => generatePDF(result, url)}>
                      <FileDown className="mr-2 h-4 w-4" />
                      Download Report
                    </Button>
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
                            className={`p-4 rounded-md ${
                              result.prediction === "bad"
                                ? "bg-red-50 dark:bg-red-900/10"
                                : "bg-green-50 dark:bg-green-900/10"
                            }`}
                          >
                            <div className="flex items-center justify-between">
                              <div className="space-y-1">
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
                              <Button
                                size="sm"
                                variant="outline"
                                onClick={() => generatePDF({ ...result.features, url: result.url, prediction: result.prediction }, result.url)}
                              >
                                <FileDown className="h-4 w-4 mr-1" />
                                Report
                              </Button>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
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