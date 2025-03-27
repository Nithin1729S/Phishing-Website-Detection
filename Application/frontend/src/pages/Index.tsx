
import { useState } from "react";
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

const Index = () => {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<PhishingResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [bulkResults, setBulkResults] = useState<BulkAnalysisResult[]>([]);
  const [bulkProgress, setBulkProgress] = useState(0);
  const [isBulkAnalyzing, setIsBulkAnalyzing] = useState(false);

  // Helper function to convert an image URL to a Base64 string
  const loadImageAsBase64 = async (url: string): Promise<string> => {
    try {
      const response = await fetch(url);
      const blob = await response.blob();
      return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onloadend = () => resolve(reader.result as string);
        reader.onerror = reject;
        reader.readAsDataURL(blob);
      });
    } catch (error) {
      console.error("Error loading image:", error);
      return "";
    }
  };

  const generatePDF = async (data: PhishingResponse | BulkAnalysisResult, urlToAnalyze: string) => {
    const pdf = new jsPDF();
    const pageWidth = pdf.internal.pageSize.getWidth();
    const pageHeight = pdf.internal.pageSize.getHeight();

    // Add a colored header background
    pdf.setFillColor(240, 240, 240);
    pdf.rect(0, 0, pageWidth, 50, 'F');

    // Load the NITK logo from the public folder (make sure nitk.png is in the public folder)
    try {
      const logoUrl = '/nitk.png';
      const logoBase64 = await loadImageAsBase64(logoUrl);
      if (logoBase64) {
        pdf.addImage(logoBase64, 'PNG', 15, 10, 30, 30);
      }
    } catch (error) {
      console.error("Error adding logo to PDF:", error);
    }

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
    pdf.save(`${urlToAnalyze.replace(/[^a-zA-Z0-9]/g, '_')}-phishing-report-${new Date().getTime()}.pdf`);
  };

  const handleUrlSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    try {
      // For demonstration, we'll simulate the API response
      // In a real application, you would uncomment the fetch code below
      
      /*
      const response = await fetch("http://localhost:8000/api/check-phishing", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const data: PhishingResponse = await response.json();
      */
      
      // Simulate API response with mock data
      setTimeout(() => {
        const isSuspicious = url.includes('phish') || url.includes('scam') || Math.random() > 0.6;
        const mockData: PhishingResponse = {
          prediction: isSuspicious ? "bad" : "good",
          url_length: url.length,
          contains_ip: url.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/) ? "yes" : "no",
          contains_at_symbol: url.includes('@') ? "yes" : "no",
          contains_double_slash: url.includes('//') ? "yes" : "no",
          contains_dash_symbol: url.includes('-') ? "yes" : "no",
          contains_subdomain: (url.match(/\./g) || []).length > 1 ? "yes" : "no",
          ssl_final_state: isSuspicious ? "invalid" : "valid",
          domain_registration_length: Math.floor(Math.random() * 365) + " days",
          favicon: Math.random() > 0.5 ? "valid" : "invalid",
          port: "standard",
          https_token: url.includes('https') ? "present" : "absent",
          request_url: Math.random() > 0.7 ? "suspicious" : "normal",
          url_of_anchor: Math.random() > 0.6 ? "suspicious" : "normal",
          links_in_tags: Math.floor(Math.random() * 50),
          sfh: Math.random() > 0.5 ? "suspicious" : "normal",
          submitting_to_email: Math.random() > 0.8 ? "yes" : "no",
          abnormal_url: isSuspicious ? "yes" : "no",
          redirect: Math.floor(Math.random() * 5),
          on_mouseover: Math.random() > 0.7 ? "changed" : "normal",
          right_click: Math.random() > 0.8 ? "disabled" : "enabled",
          popup_window: Math.random() > 0.8 ? "yes" : "no",
          iframe: Math.random() > 0.7 ? "present" : "absent",
          age_of_domain: Math.floor(Math.random() * 10) + " years",
          dns_record: isSuspicious ? "not_found" : "found",
          web_traffic: Math.floor(Math.random() * 100000),
          page_rank: (Math.random() * 10).toFixed(2),
          google_index: isSuspicious ? "not_indexed" : "indexed",
          links_pointing_to_page: Math.floor(Math.random() * 100),
          statistical_report: isSuspicious ? "suspicious" : "normal"
        };
        
        setResult(mockData);
        setIsLoading(false);
      }, 1500);
      
    } catch (error) {
      console.error("Error:", error);
      setIsLoading(false);
    }
  };

  const handleBulkAnalysis = async (file: File) => {
    setIsBulkAnalyzing(true);
    setBulkResults([]);
    setBulkProgress(0);

    Papa.parse(file, {
      complete: async (results) => {
        const urls = results.data.flat().filter(Boolean) as string[];
        const totalUrls = urls.length;
        const analysisResults: BulkAnalysisResult[] = [];

        // For demonstration, we'll simulate the API response
        for (let i = 0; i < urls.length; i++) {
          try {
            // In a real application, you would uncomment the fetch code below
            /*
            const response = await fetch("http://localhost:8000/api/check-phishing", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ url: urls[i] }),
            });
            const data = await response.json();
            */
            
            // Simulate API response
            await new Promise(resolve => setTimeout(resolve, 300));
            const currentUrl = urls[i];
            const isSuspicious = currentUrl.includes('phish') || currentUrl.includes('scam') || Math.random() > 0.6;
            
            const mockData: PhishingResponse = {
              prediction: isSuspicious ? "bad" : "good",
              url_length: currentUrl.length,
              contains_ip: currentUrl.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/) ? "yes" : "no",
              contains_at_symbol: currentUrl.includes('@') ? "yes" : "no",
              domain_registration_length: Math.floor(Math.random() * 365) + " days",
              ssl_final_state: isSuspicious ? "invalid" : "valid",
              https_token: currentUrl.includes('https') ? "present" : "absent",
              abnormal_url: isSuspicious ? "yes" : "no",
              age_of_domain: Math.floor(Math.random() * 10) + " years",
              web_traffic: Math.floor(Math.random() * 100000),
            };
            
            analysisResults.push({
              url: currentUrl,
              prediction: mockData.prediction,
              features: mockData,
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
    <div className="min-h-screen bg-gradient-to-b from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800 animate-fade-in">
      {/* Header */}
      <header className="border-b bg-white dark:bg-gray-950 shadow-sm">
        <div className="container mx-auto px-4 py-4 flex items-center">
          <div className="h-10 w-10 mr-4 bg-blue-600 rounded-full flex items-center justify-center text-white font-bold">
            N
          </div>
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
      <main className="container mx-auto px-4 py-8 animate-slide-in">
        <Card className="mb-8 overflow-hidden glass-card">
          <CardHeader className="bg-gradient-to-r from-blue-50 to-indigo-50 dark:from-blue-900/20 dark:to-indigo-900/20">
            <CardTitle className="text-2xl">
              Phishing Website Detection System [ IT352 Course Project Jan - May 2025 ]
            </CardTitle>
            <CardDescription className="text-base">
              Developed by
              <span className="font-semibold text-gray-900 dark:text-gray-100">
                {" "}
                Nithin S{" "}
              </span>{" "}
              [221IT085] 
              &
              <span className="font-semibold text-gray-900 dark:text-gray-100">
                {" "}
                Jay Chavan{" "}
              </span>{" "}
              [221IT020] 
            </CardDescription>
          </CardHeader>
        </Card>

        <Tabs defaultValue="single" className="space-y-4">
          <TabsList className="w-full max-w-md mx-auto">
            <TabsTrigger value="single" className="w-1/2">Single URL Analysis</TabsTrigger>
            <TabsTrigger value="bulk" className="w-1/2">Bulk Analysis</TabsTrigger>
          </TabsList>

          <TabsContent value="single" className="animate-scale-in">
            <Card>
              <CardHeader>
                <CardTitle>Analyze Single URL</CardTitle>
                <CardDescription>
                  Enter a URL to analyze its potential for being a phishing
                  website
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <form onSubmit={handleUrlSubmit} className="flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-2">
                  <Input
                    placeholder="Enter URL to analyze..."
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    required
                    className="flex-1"
                  />
                  <Button type="submit" disabled={isLoading} className="button-hover">
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
                  <div className="mt-6 space-y-4 animate-fade-in">
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
                    <Button onClick={() => generatePDF(result, url)} className="button-hover">
                      <FileDown className="mr-2 h-4 w-4" />
                      Download Report
                    </Button>
                    <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
                      {Object.entries(result)
                        .filter(([key]) => key !== "prediction")
                        .map(([key, value]) => (
                          <div
                            key={key}
                            className="p-4 feature-card"
                          >
                            <div className="text-sm text-gray-500 dark:text-gray-400">
                              {key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}
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

          <TabsContent value="bulk" className="animate-scale-in">
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
                    className="cursor-pointer"
                  />
                </div>

                {isBulkAnalyzing && (
                  <div className="space-y-2 animate-fade-in">
                    <Progress value={bulkProgress} className="h-2" />
                    <p className="text-sm text-gray-500">
                      Analyzing URLs... {Math.round(bulkProgress)}%
                    </p>
                  </div>
                )}

                {bulkResults.length > 0 && (
                  <div className="space-y-4 animate-fade-in">
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
                            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between">
                              <div className="space-y-1 mb-2 sm:mb-0">
                                <p className="text-sm font-medium truncate max-w-[250px] sm:max-w-[350px] md:max-w-[500px]">
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
                                onClick={() => generatePDF({ ...result.features, prediction: result.prediction } as PhishingResponse, result.url)}
                                className="button-hover"
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
};

export default Index;
