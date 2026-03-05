import { useState, useEffect } from 'react';

function FeatureExtractor({ features }) {
  return (
    <div>
      <h2>Feature Extraction</h2>
      <ul>
        {features.map((feature, index) => (
          <li key={index}>
            URL: {feature.url}, Response Time: {feature.responseTime}ms, Request Size: {feature.requestSize} bytes
          </li>
        ))}
      </ul>
    </div>
  );
}

export default FeatureExtractor;
