import React from "react";
import { DocumentVerifier } from "./components/DocumentVerifier";

export default function App() {
  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-200 flex items-center justify-center p-4">
      <DocumentVerifier />
    </div>
  );
}
