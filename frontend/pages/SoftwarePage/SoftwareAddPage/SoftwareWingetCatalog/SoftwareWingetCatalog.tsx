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

interface IProps { currentTeamId: number; }

const BASE_PATH = "/latest/fleet/communityplus/catalog";

const SoftwareWingetCatalog = ({ currentTeamId }: IProps) => {
  const [query, setQuery] = useState("");
  const queryClient = useQueryClient();
  const { data, isLoading, isError } = useQuery<{ catalog_entries: ICatalogEntry[] }>(
    ["communityplus-winget-catalog", query],
    () => sendRequest("GET", `${BASE_PATH}/winget?query=${encodeURIComponent(query)}&fleet_id=${currentTeamId}`),
    { enabled: query.trim().length >= 2 }
  );

  const addToFleet = async (entry: ICatalogEntry) => {
    try {
      await sendRequest("POST", `${BASE_PATH}/deployments`, {
        id: `winget-${currentTeamId}-${entry.id}`,
        catalog_entry_id: entry.id,
        scope: { kind: "fleet", fleet_id: currentTeamId },
        self_service: true,
        automatic: true,
        patch: true,
      });
      notify.success(`${entry.name} was added to this Fleet.`);
      queryClient.invalidateQueries("communityplus-winget-catalog");
    } catch (error) {
      notify.error("Couldn't add the WinGet package. Check your permissions and try again.");
    }
  };

  return (
    <div className="software-winget-catalog">
      <h2>WinGet catalog</h2>
      <p>Search reviewed Windows packages and add them to this Fleet with automatic installation and patching.</p>
      <input aria-label="Search WinGet catalog" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search by app name or package ID" />
      {isLoading && <Spinner />}
      {isError && <DataError verticalPaddingSize="pad-large" />}
      {data?.catalog_entries.map((entry) => (
        <div key={entry.id} className="software-winget-catalog__entry">
          <div><strong>{entry.name}</strong><br />{entry.package_identifier} · {entry.version} · {entry.installer_type.toUpperCase()}</div>
          <Button onClick={() => addToFleet(entry)}>Add to this Fleet</Button>
        </div>
      ))}
      {query.trim().length >= 2 && !isLoading && data?.catalog_entries.length === 0 && <p>No reviewed WinGet packages match this search.</p>}
    </div>
  );
};

export default SoftwareWingetCatalog;
