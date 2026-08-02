import React, { useState, useEffect } from 'react';
import { ShieldCheck, UserCheck, Trash2, Plus, Search, AlertCircle, RefreshCw, Mail, Globe } from 'lucide-react';
import { TRUSTED_SENDERS_CHANGED_EVENT, trustedSenderApi, TrustedSender } from '../services/trustedSenderApi';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';

export const TrustedSendersPage: React.FC = () => {
  const [trustedList, setTrustedList] = useState<TrustedSender[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Form states
  const [type, setType] = useState<'email' | 'domain'>('email');
  const [value, setValue] = useState<string>('');
  const [adding, setAdding] = useState<boolean>(false);
  const [formError, setFormError] = useState<string | null>(null);

  // Filter state
  const [searchQuery, setSearchQuery] = useState<string>('');

  const fetchTrustedSenders = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await trustedSenderApi.getTrustedSenders();
      setTrustedList(data);
    } catch (err: any) {
      console.error('Failed to load trusted senders:', err);
      setError(err.response?.data?.detail || err.message || 'Unable to retrieve trusted senders list.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTrustedSenders();
  }, []);

  useEffect(() => {
    const handleTrustedSendersChanged = () => {
      fetchTrustedSenders();
    };

    window.addEventListener(TRUSTED_SENDERS_CHANGED_EVENT, handleTrustedSendersChanged);
    return () => {
      window.removeEventListener(TRUSTED_SENDERS_CHANGED_EVENT, handleTrustedSendersChanged);
    };
  }, []);

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);
    const cleanValue = value.trim().toLowerCase();

    if (!cleanValue) {
      setFormError('Please enter an email or domain value.');
      return;
    }

    if (type === 'email') {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(cleanValue)) {
        setFormError('Please enter a valid email address.');
        return;
      }
    } else {
      const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/;
      if (!domainRegex.test(cleanValue)) {
        setFormError('Please enter a valid domain (e.g. google.com).');
        return;
      }
    }

    // Check client side for duplicates
    const duplicate = trustedList.find(
      (item) => item.type === type && item.value.toLowerCase() === cleanValue
    );
    if (duplicate) {
      setFormError(`This ${type} is already trusted.`);
      return;
    }

    setAdding(true);
    try {
      const newSender = await trustedSenderApi.addTrustedSender({
        type,
        value: cleanValue,
      });
      setTrustedList((prev) => [newSender, ...prev]);
      setValue('');
    } catch (err: any) {
      console.error('Failed to add trusted sender:', err);
      setFormError(err.response?.data?.detail || err.message || 'Failed to add trusted sender.');
    } finally {
      setAdding(false);
    }
  };

  const handleDelete = async (id: string) => {
    try {
      await trustedSenderApi.deleteTrustedSender(id);
      setTrustedList((prev) => prev.filter((item) => item.id !== id));
    } catch (err: any) {
      console.error('Failed to delete trusted sender:', err);
      setError(err.response?.data?.detail || err.message || 'Failed to delete trusted sender.');
    }
  };

  const filteredList = trustedList.filter((item) =>
    item.value.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Banner / Header */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-blue-900/40 via-shield-card/30 to-shield-card/50 border border-shield-border/60 p-6 md:p-8">
        <div className="absolute top-0 right-0 -mt-4 -mr-4 w-52 h-52 bg-blue-500/10 rounded-full blur-3xl pointer-events-none"></div>
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 relative z-10">
          <div className="space-y-2">
            <div className="flex items-center space-x-2.5 text-blue-400">
              <UserCheck className="w-6 h-6" />
              <h1 className="text-xl font-bold tracking-tight text-white md:text-2xl">Trusted Senders Registry</h1>
            </div>
            <p className="text-sm text-slate-400 max-w-2xl">
              Add individual email addresses or entire domains that you trust. Emails from these sources will receive a green Trusted badge and a safely reduced threat score, while maintaining rigorous background scans.
            </p>
          </div>
          <Button variant="outline" className="flex items-center gap-1.5 self-start md:self-auto bg-slate-900/40 hover:bg-slate-900/75 border-slate-700" onClick={fetchTrustedSenders}>
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Refresh</span>
          </Button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400 flex items-start space-x-3 text-sm">
          <AlertCircle className="w-5 h-5 shrink-0 mt-0.5" />
          <span>{error}</span>
        </div>
      )}

      {/* Grid: Form and list */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Form panel */}
        <div className="lg:col-span-1">
          <Card className="p-6 sticky top-6">
            <h2 className="text-md font-bold text-white mb-4">Add Trusted Sender</h2>
            <form onSubmit={handleAdd} className="space-y-4">
              <div className="space-y-2">
                <label className="text-xs font-semibold text-slate-400">Rule Type</label>
                <div className="grid grid-cols-2 gap-2 bg-slate-900/60 p-1 rounded-lg border border-slate-800">
                  <button
                    type="button"
                    onClick={() => { setType('email'); setFormError(null); }}
                    className={`flex items-center justify-center gap-1.5 py-1.5 px-3 rounded-md text-xs font-medium transition-all ${
                      type === 'email'
                        ? 'bg-blue-600 text-white shadow-sm'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <Mail className="w-3.5 h-3.5" />
                    <span>Email Address</span>
                  </button>
                  <button
                    type="button"
                    onClick={() => { setType('domain'); setFormError(null); }}
                    className={`flex items-center justify-center gap-1.5 py-1.5 px-3 rounded-md text-xs font-medium transition-all ${
                      type === 'domain'
                        ? 'bg-blue-600 text-white shadow-sm'
                        : 'text-slate-400 hover:text-slate-200'
                    }`}
                  >
                    <Globe className="w-3.5 h-3.5" />
                    <span>Entire Domain</span>
                  </button>
                </div>
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-slate-400">
                  {type === 'email' ? 'Sender Email Address' : 'Sender Domain'}
                </label>
                <div className="relative">
                  <input
                    type="text"
                    placeholder={type === 'email' ? 'security@gmail.com' : 'google.com'}
                    value={value}
                    onChange={(e) => { setValue(e.target.value); setFormError(null); }}
                    className="w-full pl-3 pr-3 py-2 text-sm rounded-lg bg-slate-900/60 border border-slate-800 text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500 transition-all font-mono"
                  />
                </div>
              </div>

              {formError && (
                <div className="p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs flex items-start space-x-2">
                  <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
                  <span>{formError}</span>
                </div>
              )}

              <Button
                variant="primary"
                type="submit"
                disabled={adding}
                className="w-full flex items-center justify-center gap-1.5 py-2"
              >
                {adding ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Adding Trust...</span>
                  </>
                ) : (
                  <>
                    <Plus className="w-4 h-4" />
                    <span>Add to Trustlist</span>
                  </>
                )}
              </Button>
            </form>
          </Card>
        </div>

        {/* List panel */}
        <div className="lg:col-span-2 space-y-4">
          {/* Search bar card */}
          <div className="relative">
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
            <input
              type="text"
              placeholder="Search trusted senders or domains..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-10 pr-4 py-2.5 rounded-xl bg-shield-card border border-shield-border/60 text-white placeholder:text-slate-500 focus:outline-none focus:border-blue-500/80 transition-all text-sm"
            />
          </div>

          <Card className="overflow-hidden">
            {loading ? (
              <div className="p-12 text-center space-y-4">
                <RefreshCw className="w-8 h-8 animate-spin text-blue-400 mx-auto" />
                <p className="text-sm text-slate-400">Loading trusted senders list...</p>
              </div>
            ) : filteredList.length === 0 ? (
              <div className="p-12 text-center max-w-md mx-auto space-y-4">
                <div className="w-12 h-12 rounded-full bg-blue-600/10 border border-blue-500/30 flex items-center justify-center mx-auto text-blue-400">
                  <ShieldCheck className="w-6 h-6" />
                </div>
                <div className="space-y-1">
                  <h3 className="text-sm font-bold text-white">No Trusted Senders</h3>
                  <p className="text-xs text-slate-400">
                    {searchQuery ? 'No trusted senders matched your search query.' : 'Your trustlist is currently empty. Add domain policies or individual emails to trust them.'}
                  </p>
                </div>
              </div>
            ) : (
              <div className="divide-y divide-slate-800/60">
                {filteredList.map((item) => (
                  <div key={item.id} className="p-4 flex items-center justify-between hover:bg-slate-800/10 transition-colors">
                    <div className="flex items-center space-x-3.5 min-w-0">
                      <div className={`w-8 h-8 rounded-lg flex items-center justify-center shrink-0 border ${
                        item.type === 'email' 
                          ? 'bg-blue-600/10 border-blue-500/30 text-blue-400' 
                          : 'bg-indigo-600/10 border-indigo-500/30 text-indigo-400'
                      }`}>
                        {item.type === 'email' ? <Mail className="w-4 h-4" /> : <Globe className="w-4 h-4" />}
                      </div>
                      <div className="min-w-0 space-y-0.5">
                        <p className="text-sm font-semibold text-white font-mono truncate">{item.value}</p>
                        <p className="text-[10px] text-slate-400">
                          Added on {new Date(item.created_at).toLocaleDateString()} &bull; Type: <span className="capitalize">{item.type}</span>
                        </p>
                      </div>
                    </div>
                    <button
                      onClick={() => handleDelete(item.id)}
                      className="p-2 text-slate-500 hover:text-rose-400 hover:bg-rose-500/10 rounded-lg transition-all"
                      title="Remove Trust Rule"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </div>
      </div>
    </div>
  );
};
