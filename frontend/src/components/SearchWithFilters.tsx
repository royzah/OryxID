import { useState, useEffect } from "react";
import { Search, Filter, X } from "lucide-react";
import { Input } from "./ui/input";
import { Button } from "./ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
  DropdownMenuCheckboxItem,
} from "./ui/dropdown-menu";
import { Badge } from "./ui/badge";
import { useDebounce } from "@/hooks/useDebounce";

interface Filter {
  id: string;
  label: string;
  value: string;
}

interface SearchWithFiltersProps {
  placeholder?: string;
  onSearch: (query: string) => void;
  onFiltersChange?: (filters: Filter[]) => void;
  availableFilters?: {
    label: string;
    options: Filter[];
  }[];
}

export function SearchWithFilters({
  placeholder = "Search...",
  onSearch,
  onFiltersChange,
  availableFilters = [],
}: SearchWithFiltersProps) {
  const [query, setQuery] = useState("");
  const [activeFilters, setActiveFilters] = useState<Filter[]>([]);
  const debouncedQuery = useDebounce(query, 300);

  useEffect(() => {
    onSearch(debouncedQuery);
  }, [debouncedQuery, onSearch]);

  const toggleFilter = (filter: Filter) => {
    const newFilters = activeFilters.some((f) => f.id === filter.id)
      ? activeFilters.filter((f) => f.id !== filter.id)
      : [...activeFilters, filter];

    setActiveFilters(newFilters);
    onFiltersChange?.(newFilters);
  };

  const clearFilters = () => {
    setActiveFilters([]);
    onFiltersChange?.([]);
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-400" />
          <Input
            placeholder={placeholder}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="pl-10"
          />
        </div>

        {availableFilters.length > 0 && (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="icon">
                <Filter className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-56">
              {availableFilters.map((group, index) => (
                <div key={group.label}>
                  {index > 0 && <DropdownMenuSeparator />}
                  <DropdownMenuLabel>{group.label}</DropdownMenuLabel>
                  {group.options.map((filter) => (
                    <DropdownMenuCheckboxItem
                      key={filter.id}
                      checked={activeFilters.some((f) => f.id === filter.id)}
                      onCheckedChange={() => toggleFilter(filter)}
                    >
                      {filter.label}
                    </DropdownMenuCheckboxItem>
                  ))}
                </div>
              ))}
            </DropdownMenuContent>
          </DropdownMenu>
        )}
      </div>

      {activeFilters.length > 0 && (
        <div className="flex items-center gap-2">
          <span className="text-sm text-gray-500">Active filters:</span>
          <div className="flex flex-wrap gap-2">
            {activeFilters.map((filter) => (
              <Badge key={filter.id} variant="secondary" className="gap-1">
                {filter.label}
                <button
                  onClick={() => toggleFilter(filter)}
                  className="ml-1 hover:text-destructive"
                >
                  <X className="h-3 w-3" />
                </button>
              </Badge>
            ))}
          </div>
          <Button
            variant="ghost"
            size="sm"
            onClick={clearFilters}
            className="ml-auto"
          >
            Clear all
          </Button>
        </div>
      )}
    </div>
  );
}
