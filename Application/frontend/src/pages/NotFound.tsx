
import { useLocation } from "react-router-dom";
import { useEffect } from "react";
import { Button } from "@/components/ui/button";
import { ArrowLeft } from "lucide-react";

const NotFound = () => {
  const location = useLocation();

  useEffect(() => {
    console.error(
      "404 Error: User attempted to access non-existent route:",
      location.pathname
    );
  }, [location.pathname]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-b from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800 animate-fade-in">
      <div className="text-center p-8 glass-card rounded-xl shadow-lg max-w-md">
        <h1 className="text-6xl font-bold mb-4 text-blue-600 dark:text-blue-400">404</h1>
        <p className="text-xl text-gray-700 dark:text-gray-300 mb-6">The page you're looking for doesn't exist</p>
        <Button className="button-hover" asChild>
          <a href="/">
            <ArrowLeft className="mr-2 h-4 w-4" />
            Return to Home
          </a>
        </Button>
      </div>
    </div>
  );
};

export default NotFound;
