import { useState, useEffect } from 'react';

function SourceTracer({ traced }) {
  return (
    <div>
      <h2>Source Tracing</h2>
      <ul>
        {traced.map((item, index) => (
          <li key={index}>
            Source IP: {item.sourceIP}, Session: {item.session}, URL: {item.url}
          </li>
        ))}
      </ul>
    </div>
  );
}

export default SourceTracer;
