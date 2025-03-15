import { NextResponse } from 'next/server';

// This is a mock API response. Replace with your actual backend integration
export async function POST(req: Request) {
  const { url } = await req.json();

  // Simulate API delay
  await new Promise((resolve) => setTimeout(resolve, 1000));

  // Mock response - replace with actual backend call
  const mockResponse = {
    isPhishing: Math.random() > 0.5, // Random result for demo
    features: {
      'URL Length': url.length,
      'Contains HTTPS': url.startsWith('https') ? 'Yes' : 'No',
      'Domain Age': '2 years',
      'Special Characters': (url.match(/[^a-zA-Z0-9]/g) || []).length,
      'IP Address Present': url.match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/) ? 'Yes' : 'No',
      'Subdomain Count': url.split('.').length - 1,
      'URL Entropy': calculateEntropy(url),
      'TLD Type': url.split('.').pop(),
      'Domain Length': url.split('/')[2]?.length || 0,
      'Path Length': url.split('?')[0].split('/').slice(3).join('/').length,
    },
  };

  return NextResponse.json(mockResponse);
}

// Helper function to calculate URL entropy
function calculateEntropy(str: string): number {
  const len = str.length;
  const frequencies = new Map();
  
  for (const char of str) {
    frequencies.set(char, (frequencies.get(char) || 0) + 1);
  }
  
  return Array.from(frequencies.values()).reduce((entropy, freq) => {
    const probability = freq / len;
    return entropy - probability * Math.log2(probability);
  }, 0).toFixed(2);
}