import React, { useState } from "react";
import { useQuery, useQueryClient } from "react-query";

import Button from "components/buttons/Button";
import DataError from "components/DataError";
import Spinner from "components/Spinner";
import { notify } from "components/ToastNotification";
import sendRequest from "services";

interface ICatalogEntry {
  id: string;
  package_identifier: string;
  name: string;
  version: string;
  installer_type: string;
}

interface IUpstreamEntry {
  display_name: string;
  package_identifier: string;
  version: string;
  installer_type: string;
  source_url: string;
  source_sha256: string;
}

interface IProps { currentTeamId: number; }

const BASE_PATH = "/latest/fleet/communityplus/catalog";

const SoftwareWingetCatalog = ({ currentTeamId }: IProps) => {
  const [query, setQuery] = useState("");
  const queryClient = useQueryClient();
  const { data, isLoading, isError } = useQuery<{ upstream_entries: IUpstreamEntry[] }>(
    ["communityplus-winget-upstream", query],
    () => sendRequest("GET", `${BASE_PATH}/winget/upstream?query=${encodeURIComponent(query)}`),
    { enabled: query.trim().length >= 2 }
  );

  const importAndAddToFleet = async (entry: IUpstreamEntry) => {
    try {
      const imported: { catalog_entry: ICatalogEntry } = await sendRequest("POST", `${BASE_PATH}/winget/import`, {
        source_url: entry.source_url,
        source_sha256: entry.source_sha256,
        display_name: entry.display_name,
      });
      await sendRequest("POST", `${BASE_PATH}/deployments`, {
        id: `winget-${currentTeamId}-${imported.catalog_entry.id}`,
        catalog_entry_id: imported.catalog_entry.id,
        scope: { kind: "fleet", fleet_id: currentTeamId },
        self_service: true,
        automatic: true,
        patch: true,
      });
      notify.success(`${entry.display_name} was added to this Fleet.`);
      queryClient.invalidateQueries("communityplus-winget-upstream");
    } catch (error) {
      notify.error("Couldn't add the WinGet package. Check your permissions and try again.");
    }
  };

  return (
    <div className="software-winget-catalog">
      <h2>WinGet catalog</h2>
      <p>Search the official WinGet source. Fleet verifies and imports the exact manifest before adding it to this Fleet.</p>
      <input aria-label="Search WinGet catalog" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search by app name or package ID" />
      {isLoading && <Spinner />}
      {isError && <DataError verticalPaddingSize="pad-large" />}
      {data?.upstream_entries.map((entry) => (
        <div key={entry.source_url} className="software-winget-catalog__entry">
          <div><strong>{entry.display_name}</strong><br />{entry.package_identifier} · {entry.version} · {entry.installer_type.toUpperCase()}</div>
          <Button onClick={() => importAndAddToFleet(entry)}>Import and add to this Fleet</Button>
        </div>
      ))}
      {query.trim().length >= 2 && !isLoading && data?.upstream_entries.length === 0 && <p>No supported WinGet packages match this search.</p>}
    </div>
  );
};

export default SoftwareWingetCatalog;
