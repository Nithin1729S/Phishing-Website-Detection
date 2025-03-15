'use client';

import { useState } from 'react';
import { Shield, ShieldAlert, ChevronDown, ChevronUp, Globe } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card } from '@/components/ui/card';
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible';

interface PhishingResponse {
  isPhishing: boolean;
  features: { [key: string]: string | number };
}

export default function Home() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<PhishingResponse | null>(null);
  const [isOpen, setIsOpen] = useState(false);

  const checkUrl = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    try {
      // Replace with your actual API endpoint
      const response = await fetch('/api/check-phishing', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });
      const data = await response.json();
      setResult(data);
    } catch (error) {
      console.error('Error:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <main className="min-h-screen bg-gradient-to-b from-background to-secondary p-4">
      <div className="max-w-3xl mx-auto space-y-8 pt-12">
        <div className="text-center space-y-4">
          <h1 className="text-4xl font-bold tracking-tight">
            Phishing URL Detection
          </h1>
          <p className="text-muted-foreground">
            Enter a URL to check if it&apos;s potentially malicious
          </p>
        </div>

        <Card className="p-6">
          <form onSubmit={checkUrl} className="space-y-4">
            <div className="flex gap-2">
              <Input
                type="url"
                placeholder="Enter URL to check..."
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                className="flex-1"
                required
              />
              <Button type="submit" disabled={loading}>
                {loading ? (
                  'Checking...'
                ) : (
                  <>
                    <Shield className="mr-2 h-4 w-4" />
                    Check URL
                  </>
                )}
              </Button>
            </div>

            {result && (
              <div className="space-y-4">
                <div
                  className={`p-4 rounded-lg flex items-center gap-3 ${
                    result.isPhishing
                      ? 'bg-destructive/10 text-destructive'
                      : 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400'
                  }`}
                >
                  {result.isPhishing ? (
                    <ShieldAlert className="h-5 w-5" />
                  ) : (
                    <Shield className="h-5 w-5" />
                  )}
                  <span className="font-medium">
                    {result.isPhishing
                      ? 'Warning: Potential phishing URL detected!'
                      : 'Safe: This URL appears to be legitimate.'}
                  </span>
                </div>

                <Collapsible open={isOpen} onOpenChange={setIsOpen}>
                  <CollapsibleTrigger asChild>
                    <Button
                      variant="outline"
                      className="w-full flex justify-between"
                    >
                      <span>URL Analysis Features</span>
                      {isOpen ? (
                        <ChevronUp className="h-4 w-4" />
                      ) : (
                        <ChevronDown className="h-4 w-4" />
                      )}
                    </Button>
                  </CollapsibleTrigger>
                  <CollapsibleContent className="mt-4">
                    <div className="space-y-2">
                      {Object.entries(result.features).map(([key, value]) => (
                        <div
                          key={key}
                          className="flex justify-between py-2 px-4 odd:bg-muted/50 rounded"
                        >
                          <span className="font-medium">{key}</span>
                          <span className="text-muted-foreground">{value}</span>
                        </div>
                      ))}
                    </div>
                  </CollapsibleContent>
                </Collapsible>
              </div>
            )}
          </form>
        </Card>

        <div className="text-center text-sm text-muted-foreground">
          <p>
            Protect yourself from phishing attacks by verifying suspicious URLs
            before clicking.
          </p>
        </div>
      </div>
    </main>
  );
}