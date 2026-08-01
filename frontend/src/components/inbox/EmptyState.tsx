import React from 'react';
import { Mail, SearchX, RefreshCw } from 'lucide-react';
import { Card } from '../ui/Card';
import { Button } from '../ui/Button';

interface EmptyStateProps {
  isSearch?: boolean;
  onRefresh?: () => void;
}

export const EmptyState: React.FC<EmptyStateProps> = ({ isSearch = false, onRefresh }) => {
  return (
    <Card className="p-12 text-center space-y-4 max-w-md mx-auto my-8 border-dashed border-slate-800">
      <div className="p-4 rounded-2xl bg-blue-600/10 border border-blue-500/20 text-blue-400 inline-flex mx-auto">
        {isSearch ? <SearchX className="w-10 h-10 text-amber-400" /> : <Mail className="w-10 h-10 text-blue-400" />}
      </div>
      <div className="space-y-1">
        <h3 className="text-lg font-bold text-white">
          {isSearch ? 'No Matching Messages Found' : 'No Emails Synced Yet'}
        </h3>
        <p className="text-xs text-slate-400 leading-relaxed">
          {isSearch
            ? 'Try adjusting your search criteria, sender email, or keyword query.'
            : 'Click the sync button to retrieve your latest 20 messages from Gmail.'}
        </p>
      </div>

      {onRefresh && (
        <Button size="sm" variant="outline" onClick={onRefresh} className="mt-2">
          <RefreshCw className="w-3.5 h-3.5 mr-1.5" />
          Sync Inbox
        </Button>
      )}
    </Card>
  );
};
