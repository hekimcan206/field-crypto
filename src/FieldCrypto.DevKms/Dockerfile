# syntax=docker/dockerfile:1

# ---- build -------------------------------------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/sdk:10.0-alpine AS build
WORKDIR /src

# Restore in its own layer: it only re-runs when package versions or project files change. The cache mount is locked
# because compose builds two images from this repository at once.
COPY global.json Directory.Build.props Directory.Packages.props ./
COPY src/FieldCrypto/FieldCrypto.csproj src/FieldCrypto/
COPY src/FieldCrypto.Oci/FieldCrypto.Oci.csproj src/FieldCrypto.Oci/
COPY src/FieldCrypto.DevKms/FieldCrypto.DevKms.csproj src/FieldCrypto.DevKms/
RUN --mount=type=cache,id=fieldcrypto-nuget,target=/root/.nuget/packages,sharing=locked \
    dotnet restore src/FieldCrypto.DevKms/FieldCrypto.DevKms.csproj

COPY .editorconfig ./
COPY src/FieldCrypto/ src/FieldCrypto/
COPY src/FieldCrypto.Oci/ src/FieldCrypto.Oci/
COPY src/FieldCrypto.DevKms/ src/FieldCrypto.DevKms/
RUN --mount=type=cache,id=fieldcrypto-nuget,target=/root/.nuget/packages,sharing=locked \
    dotnet publish src/FieldCrypto.DevKms/FieldCrypto.DevKms.csproj \
        --configuration Release --output /app/publish -p:UseAppHost=false \
    && mkdir -p /out/client /out/state

# ---- runtime -----------------------------------------------------------------------------------------
# Chiseled Ubuntu: no shell, no package manager, non-root "app" user (UID 1654).
FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled AS runtime
LABEL org.opencontainers.image.title="fieldcrypto-devkms" \
      org.opencontainers.image.description="Development KMS (OCI Vault API subset). Not for real data." \
      org.opencontainers.image.source="https://github.com/hekimcan206/field-crypto" \
      org.opencontainers.image.licenses="MIT"
WORKDIR /app
COPY --from=build --link /app/publish .
# Owned by the app user, so fresh named volumes mounted here inherit that ownership.
COPY --from=build --chown=1654:1654 /out/client /client
COPY --from=build --chown=1654:1654 /out/state /state
USER $APP_UID
ENV ASPNETCORE_URLS=http://+:8080 \
    DevKms__ClientKeyDirectory=/client \
    DevKms__StatePath=/state/master-keys.json
EXPOSE 8080
ENTRYPOINT ["dotnet", "FieldCrypto.DevKms.dll"]
