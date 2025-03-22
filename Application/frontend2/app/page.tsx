'use client';

import { useState } from 'react';
import Image from 'next/image';
import { Building2, FileDown, Link, Shield, Upload } from 'lucide-react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";

export default function Home() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState<null | {
    prediction: boolean;
    features: Record<string, any>;
  }>(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleUrlSubmit = async () => {
    setIsLoading(true);
    // TODO: Replace with actual API call
    setTimeout(() => {
      setResult({
        prediction: Math.random() > 0.5,
        features: {
          'Domain Age': '2 years',
          'SSL Certificate': 'Valid',
          'IP Location': 'United States',
          'Domain Registration': 'Verified',
          'Suspicious TLD': 'No',
          'URL Length': '32 characters',
        }
      });
      setIsLoading(false);
    }, 1500);
  };

  const handleBulkAnalysis = async (file: File) => {
    // TODO: Implement bulk analysis
    console.log('Processing file:', file.name);
  };

  const downloadReport = () => {
    // TODO: Implement PDF generation and download
    console.log('Downloading report...');
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
            <CardTitle>Phishing Website Detection System [ IT352 Course Project ]</CardTitle>
            <CardDescription>
              Analyze URLs to detect potential phishing websites using advanced machine learning algorithms
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
                  Enter a URL to analyze its potential for being a phishing website
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex space-x-2">
                  <Input
                    placeholder="Enter URL to analyze..."
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                  />
                  <Button onClick={handleUrlSubmit} disabled={isLoading}>
                    {isLoading ? (
                      "Analyzing..."
                    ) : (
                      <>
                        <Link className="mr-2 h-4 w-4" />
                        Analyze
                      </>
                    )}
                  </Button>
                </div>

                {result && (
                  <div className="mt-6 space-y-4">
                    <div className={`p-4 rounded-lg ${
                      result.prediction
                        ? 'bg-red-100 text-red-700 dark:bg-red-900/20 dark:text-red-400'
                        : 'bg-green-100 text-green-700 dark:bg-green-900/20 dark:text-green-400'
                    }`}>
                      <h3 className="font-semibold">
                        {result.prediction ? 'Potential Phishing Website Detected!' : 'Website Appears Safe'}
                      </h3>
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                      {Object.entries(result.features).map(([key, value]) => (
                        <div key={key} className="p-4 bg-white dark:bg-gray-800 rounded-lg shadow-sm">
                          <div className="text-sm text-gray-500 dark:text-gray-400">{key}</div>
                          <div className="font-medium">{value}</div>
                        </div>
                      ))}
                    </div>

                    <Button onClick={downloadReport}>
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
                  Upload a CSV/Excel file containing URLs for batch analysis
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Label htmlFor="file" className="block mb-2">Upload File</Label>
                <Input
                  id="file"
                  type="file"
                  accept=".csv,.xlsx,.xls"
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    if (file) handleBulkAnalysis(file);
                  }}
                />
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </main>

      {/* Footer */}
      <footer className="border-t bg-white dark:bg-gray-950 mt-8">
        <div className="container mx-auto px-4 py-6">
          <p className="text-center text-gray-600 dark:text-gray-400">
            Developed by Nithin S [ 221IT085 ] | © {new Date().getFullYear()}
          </p>
        </div>
      </footer>
    </div>
  );
}